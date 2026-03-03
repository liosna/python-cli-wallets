#!/usr/bin/env python3

import argparse
import os
import re
import sys
import base64
import getpass
import requests
import ctypes
import gc

# Import for the 'bit' library - handles all key/tx operations
from bit import Key as BitKey
from bit import PrivateKeyTestnet
from bit.network import NetworkAPI
from bit.format import address_to_scriptpubkey

# Imports for cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

# =======================
# UTILS
# =======================

def set_owner_only_permissions(path: str) -> None:
    """
    Best-effort: set file perms to owner read/write only (0600) on Unix.
    On Windows this may do nothing useful; we ignore failures.
    """
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass

def is_valid_btc_address(addr: str) -> bool:
    try:
        address_to_scriptpubkey(addr)  # will decode and fail on invalid format
        return True
    except Exception:
        return False
    
def mask_wif(wif_text: str, show_start: int = 4, show_end: int = 4) -> str:
    if len(wif_text) <= show_start + show_end:
        return "*" * len(wif_text)
    return f"{wif_text[:show_start]}{'*' * (len(wif_text) - show_start - show_end)}{wif_text[-show_end:]}"

def secure_zero_bytearray(b: bytearray) -> None:
    # Overwrite the bytearray in place
    for i in range(len(b)):
        b[i] = 0

    # Extra attempt: ask libc memset to overwrite the same buffer
    # (Not a guarantee, but harmless.)
    buf = (ctypes.c_char * len(b)).from_buffer(b)
    ctypes.memset(ctypes.addressof(buf), 0, len(b))


def get_wallet_file(network, name):
    home = os.path.expanduser("~")
    filename = f".wallet_{network}_{name}.key"
    return os.path.join(home, filename)

def validate_name(name):
    return bool(re.fullmatch(r"[a-zA-Z]{1,4}", name))


# =======================
# ENCRYPTION
# =======================

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


# =======================
# COMMAND: GENERATE
# =======================

def generate_wallet(network):
    print("\n🪙 Generate New Wallet")

    name = input("Choose wallet name (1–4 letters): ").strip()
    if not validate_name(name):
        print("\n❌ Invalid wallet name! Must be 1–4 letters only.")
        return

    password = getpass.getpass("Choose passphrase to encrypt your wallet: ").strip()
    if not password:
        print("\n❌ Passphrase cannot be empty.")
        return

    # --- BIT REPLACEMENT ---
    # Create key using bit library
    if network == 'testnet':
        key = PrivateKeyTestnet()
    else:
        key = BitKey()

    salt = os.urandom(16)
    derived_key = derive_key(password, salt)
    fernet = Fernet(derived_key)
    
    # Get WIF from bit key
    encrypted_wif = fernet.encrypt(key.to_wif().encode())
    # --- END REPLACEMENT ---

    wallet_file = get_wallet_file(network, name)
    with open(wallet_file, "wb") as f:
        f.write(salt + encrypted_wif)
    set_owner_only_permissions(wallet_file)

    print(f"\n✅ New wallet saved: {wallet_file}")
    # Get address from bit key
    print(f"Address: {key.address}")


# =======================
# COMMAND: IMPORT
# =======================

def import_key(network):
    print("\n🔑 Import Existing WIF Private Key")

    wif_input = input("Enter your WIF private key: ").strip()
    if not wif_input:
        print("\n❌ WIF cannot be empty.")
        return
    
    # We can validate the WIF using 'bit'
    try:
        if network == 'testnet':
            PrivateKeyTestnet(wif_input)
        else:
            BitKey(wif_input)
        print("✅ WIF format appears valid.")
    except Exception as e:
        print(f"❌ Invalid WIF for {network}: {e}")
        return

    name = input("Choose wallet name (1–4 letters): ").strip()
    if not validate_name(name):
        print("\n❌ Invalid wallet name! Must be 1–4 letters only.")
        return

    password = getpass.getpass("Choose passphrase to encrypt your wallet: ").strip()
    if not password:
        print("\n❌ Passphrase cannot be empty.")
        return

    salt = os.urandom(16)
    derived_key = derive_key(password, salt)
    fernet = Fernet(derived_key)
    encrypted_wif = fernet.encrypt(wif_input.encode())

    wallet_file = get_wallet_file(network, name)
    with open(wallet_file, "wb") as f:
        f.write(salt + encrypted_wif)
    set_owner_only_permissions(wallet_file)

    print(f"\n✅ Imported private key saved as: {wallet_file}")


# =======================
# LOADING WIF HELPER
# =======================

def load_wif_from_file(network):
    name = input("Enter your wallet name (1–4 letters): ").strip()
    if not validate_name(name):
        print("\n❌ Invalid wallet name!")
        return None, None

    wallet_file = get_wallet_file(network, name)
    if not os.path.exists(wallet_file):
        print("\n❌ Wallet file not found!")
        return None, None

    password = getpass.getpass("Enter your passphrase: ").strip()

    with open(wallet_file, "rb") as f:
        data = f.read()

    salt = data[:16]
    encrypted_data = data[16:]

    try:
        derived_key = derive_key(password, salt)
        fernet = Fernet(derived_key)
        wif_ba = bytearray(fernet.decrypt(encrypted_data))
        del derived_key, data, encrypted_data, salt
        return wif_ba, name
    except (InvalidToken, UnicodeDecodeError):
        print("\n❌ Wrong passphrase! Decryption failed.")
        return None, None


# =======================
# COMMAND: LOAD
# =======================

def load_key(network):
    print("\n🔓 Load Wallet")
    wif_ba, name = load_wif_from_file(network)
    if not wif_ba:
        return
    key = None
    try:
        # Decode only for the moment you must (bit library needs str)
        wif_str = wif_ba.decode("utf-8")

        try:
            if network == 'testnet':
                key = PrivateKeyTestnet(wif_str)
            else:
                key = BitKey(wif_str)
        except Exception as e:
            print(f"❌ Error loading WIF into 'bit' library: {e}")
            return
        finally:
            # Reduce lifetime of decoded string reference
            del wif_str

        print(f"\n✅ Loaded wallet: {name}")
        print("\n⚠️  WARNING: Showing your private key can let anyone steal your funds.")

        confirm1 = input("Type FULL to begin full reveal, or press Enter to cancel: ").strip().upper()
        if confirm1 == "FULL":
            confirm2 = input("Type I UNDERSTAND to confirm: ").strip().upper()
            if confirm2 == "I UNDERSTAND":
                # Presence check: require last 4 chars
                last4 = wif_ba.decode("utf-8")[-4:]
                confirm3 = input("Type the LAST 4 characters: ").strip()
                if confirm3 == last4:
                    print("Private Key (WIF): " + wif_ba.decode("utf-8"))
                else:
                    print("❌ Check failed. Private key not shown.")
                del last4, confirm3
            else:
                print("✅ Private key not shown.")
        else:
            print("✅ Private key not shown.")

        print(f"Address: {key.address}")

    finally:
        # Best-effort wipe the decrypted WIF bytes no matter what
        try:
            secure_zero_bytearray(wif_ba)
        except Exception:
            pass
        del wif_ba
        gc.collect()
        


# =======================
# COMMAND: ADDRESS
# =======================

def show_address(network):
    print("\n📬 Show Wallet Address")
    wif_ba, name = load_wif_from_file(network)
    if not wif_ba:
        return
        
    try:
        # Decode only for the moment you must (bit library needs str)
        wif_str = wif_ba.decode("utf-8")
        try:
            key = PrivateKeyTestnet(wif_str) if network == "testnet" else BitKey(wif_str)
        finally:
            del wif_str
        print(f"\n✅ Wallet: {name}")
        print(f"Address: {key.address}")
    except Exception as e:
            print(f"❌ Error loading WIF into 'bit' library: {e}")
            return
    finally:
        secure_zero_bytearray(wif_ba)
        del wif_ba
        gc.collect()
    


# =======================
# COMMAND: BALANCE
# =======================

def check_balance(network):
    print("\n💰 Check Wallet Balance")
    wif_ba, name = load_wif_from_file(network)
    if not wif_ba:
        return
        
    try:
        # Decode only for the moment you must (bit library needs str)
        wif_str = wif_ba.decode("utf-8")
        try:
            key = PrivateKeyTestnet(wif_str) if network == "testnet" else BitKey(wif_str)
        finally:
            del wif_str
        print(f"\n✅ Wallet: {name}")
        print(f"Address: {key.address}")

    # Blockstream API
        if network == 'testnet':
            url = f"https://blockstream.info/testnet/api/address/{key.address}"
        else:
            url = f"https://blockstream.info/api/address/{key.address}"

        try:
            resp = requests.get(url)
            resp.raise_for_status() # Raise error for bad responses (4xx, 5xx)
            data = resp.json()
            confirmed = data.get('chain_stats', {}).get('funded_txo_sum', 0) - data.get('chain_stats', {}).get('spent_txo_sum', 0)
            confirmed_btc = confirmed / 1e8
            print(f"✅ Confirmed Balance: {confirmed_btc:.8f} BTC")
        except requests.exceptions.HTTPError as http_err:
            print(f"❌ HTTP error fetching balance: {http_err}")
        except Exception as e:
            print(f"❌ Error fetching balance: {e}")
    except Exception as e:
            print(f"❌ Error loading WIF into 'bit' library: {e}")
            return
    finally:
        secure_zero_bytearray(wif_ba)
        del wif_ba
        gc.collect()


# =======================
# COMMAND: SEND (Uses 'bit' library)
# =======================

def send_transaction(network):
    print("\n🚀 Send Transaction")
    wif_ba, name = load_wif_from_file(network)
    if not wif_ba:
        return

    print(f"\n✅ Sending from wallet: {name}")

    print("\n🟣 Enter recipient details")
    to_address = input("Recipient Bitcoin address: ").strip()
    if not is_valid_btc_address(to_address):
        print("\n❌ Invalid recipient address entered.")
        return

    try:
        amount_btc_str = input("Amount to send (in BTC): ").strip()
        amount_btc = float(amount_btc_str)
        if amount_btc <= 0:
            print("\n❌ Amount must be positive.")
            return
    except ValueError:
        print("\n❌ Invalid amount entered.")
        return

    fee_sat_per_byte = 2
    print(f"Fee rate: {fee_sat_per_byte} sat/byte")

    print("\n🛠️ Building transaction...")
    try:
        wif_str = wif_ba.decode("utf-8")
        try:
            tx_hex = build_and_sign_tx_with_bit(wif_str, to_address, amount_btc, fee_sat_per_byte, network)
        finally:
            del wif_str
            
        if not tx_hex:
            return
    except Exception as e:
        print(f"❌ Error building transaction: {e}")
        return
    finally:
        secure_zero_bytearray(wif_ba)
        del wif_ba
        gc.collect()


    print(f"✅ TX hex to broadcast: {tx_hex}")
    # ---- Confirm before broadcast ----
    print("\n📄 Transaction ready to broadcast")
    print(f"Network:   {network}")
    print(f"To:        {to_address}")
    print(f"Amount:    {amount_btc:.8f} BTC")
    print(f"Fee rate:  {fee_sat_per_byte} sat/byte")
    print(f"Raw TX:    {tx_hex[:32]}...{tx_hex[-32:]}")  # preview only (not full spam)

    # Strong confirmation to prevent accidents
    confirm = input("\nType 'broadcast' to send, or anything else to cancel: ").strip().lower()
    if confirm != "broadcast":
        print("❎ Broadcast cancelled.")
        return

    # Pick endpoint once
    try:
        if network == "testnet":
            txid = NetworkAPI.broadcast_tx_testnet(tx_hex)
        else:
            txid = NetworkAPI.broadcast_tx(tx_hex)

        if txid:
            print("✅ Transaction broadcast successfully!")
            print(f"🔗 TXID: {txid}")

    except Exception as e:
        print(f"❌ Broadcast failed via bit: {e}")


# =========================================================
# BUILD AND SIGN (Already uses 'bit' library)
# =========================================================

def build_and_sign_tx_with_bit(wif, to_address, amount_btc, fee_sat_per_byte, network):
    """
    Builds and signs a transaction using the 'bit' library's dedicated
    classes and automatic change handling.
    """
    # Use the correct class based on the network.
    if network == 'testnet':
        print("✅ Using Testnet key...")
        key = PrivateKeyTestnet(wif)
    else:
        print("✅ Using Mainnet key...")
        key = BitKey(wif)

    print(f"✅ Wallet address from 'bit' library: {key.address}")

    outputs = [
        (to_address, amount_btc, 'btc')
    ]

    try:
        # 'bit' library handles change automatically
        # by sending it back to the key's own address.
        tx_hex = key.create_transaction(outputs, fee=fee_sat_per_byte)
        return tx_hex
    except Exception as e:
        print(f"❌ Error from 'bit' library: {e}")
        return None


# =======================
# MAIN
# =======================

def main():
    parser = argparse.ArgumentParser(description="CLI Bitcoin Wallet with Encryption (bit-based)")
    parser.add_argument('command', choices=['generate', 'load', 'address', 'balance', 'import', 'send'], help="Command to run")
    parser.add_argument('--network', choices=['mainnet', 'testnet'], default='testnet', help="Bitcoin network (default: testnet)")

    args = parser.parse_args()

    try:
        if args.command == 'generate':
            generate_wallet(args.network)
        elif args.command == 'load':
            load_key(args.network)
        elif args.command == 'address':
            show_address(args.network)
        elif args.command == 'balance':
            check_balance(args.network)
        elif args.command == 'import':
            import_key(args.network)
        elif args.command == 'send':
            send_transaction(args.network)
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
