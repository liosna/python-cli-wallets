#!/usr/bin/env python3

import argparse
import os
import re
import sys
import base64
import getpass
import requests
import traceback

# Import for the 'bit' library - handles all key/tx operations
from bit import Key as BitKey
from bit import PrivateKeyTestnet

# Imports for cryptography
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend

# =======================
# UTILS
# =======================

# No longer needed, bit uses 'testnet' or mainnet (default)
# def map_network(user_network):
#     if user_network == 'mainnet':
#         return 'bitcoin'
#     return user_network

def get_wallet_file(network, name):
    home = os.path.expanduser("~")
    filename = f".thesis_wallet_{network}_{name}.key"
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
        wif = fernet.decrypt(encrypted_data).decode()
        return wif, name
    except (InvalidToken, UnicodeDecodeError):
        print("\n❌ Wrong passphrase! Decryption failed.")
        return None, None


# =======================
# COMMAND: LOAD
# =======================

def load_key(network):
    print("\n🔓 Load Wallet")
    wif, name = load_wif_from_file(network)
    if not wif:
        return
        
    # --- BIT REPLACEMENT ---
    try:
        if network == 'testnet':
            key = PrivateKeyTestnet(wif)
        else:
            key = BitKey(wif)
    except Exception as e:
        print(f"❌ Error loading WIF into 'bit' library: {e}")
        return
    # --- END REPLACEMENT ---

    print(f"\n✅ Loaded wallet: {name}")
    print(f"Private Key (WIF): {wif}")
    # Get address from bit key
    print(f"Address: {key.address}")


# =======================
# COMMAND: ADDRESS
# =======================

def show_address(network):
    print("\n📬 Show Wallet Address")
    wif, name = load_wif_from_file(network)
    if not wif:
        return
        
    # --- BIT REPLACEMENT ---
    try:
        if network == 'testnet':
            key = PrivateKeyTestnet(wif)
        else:
            key = BitKey(wif)
    except Exception as e:
        print(f"❌ Error loading WIF into 'bit' library: {e}")
        return
    # --- END REPLACEMENT ---

    print(f"\n✅ Wallet: {name}")
    # Get address from bit key
    print(f"Address: {key.address}")


# =======================
# COMMAND: BALANCE
# =======================

def check_balance(network):
    print("\n💰 Check Wallet Balance")
    wif, name = load_wif_from_file(network)
    if not wif:
        return
        
    # --- BIT REPLACEMENT ---
    try:
        if network == 'testnet':
            key = PrivateKeyTestnet(wif)
        else:
            key = BitKey(wif)
        # Get address from bit key
        address = key.address
    except Exception as e:
        print(f"❌ Error loading WIF into 'bit' library: {e}")
        return
    # --- END REPLACEMENT ---

    print(f"\n✅ Wallet: {name}")
    print(f"Address: {address}")

    # Blockstream API
    if network == 'testnet':
        url = f"https://blockstream.info/testnet/api/address/{address}"
    else:
        url = f"https://blockstream.info/api/address/{address}"

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


# =======================
# COMMAND: SEND (Uses 'bit' library)
# =======================

def send_transaction(network):
    print("\n🚀 Send Transaction")
    wif, name = load_wif_from_file(network)
    if not wif:
        return

    print(f"\n✅ Sending from wallet: {name}")

    print("\n🟣 Enter recipient details")
    to_address = input("Recipient Bitcoin address: ").strip()
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
        tx_hex = build_and_sign_tx_with_bit(wif, to_address, amount_btc, fee_sat_per_byte, network)
        if not tx_hex:
            return
    except Exception as e:
        print(f"❌ Error building transaction: {e}")
        traceback.print_exc()
        return

    print(f"✅ TX hex to broadcast: {tx_hex}")
    print("\n🌐 Broadcasting transaction...")

    if network == 'testnet':
        push_url = "https://blockstream.info/testnet/api/tx"
    else:
        push_url = "https://blockstream.info/api/tx"
    try:
        resp = requests.post(push_url, data=tx_hex, timeout=15)
        if resp.status_code == 200:
            print("✅ Transaction broadcast successfully!")
            print(f"🔗 TXID: {resp.text.strip()}")
        else:
            print(f"❌ Broadcast failed with HTTP {resp.status_code}: {resp.text.strip()}")
    except requests.exceptions.Timeout:
        print("❌ Error: Broadcast request timed out. Please try again.")
    except requests.exceptions.RequestException as e:
        print(f"❌ Network error during broadcast: {e}")


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
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
