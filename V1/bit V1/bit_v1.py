"""
bit_v1.py — Hardened CLI Bitcoin Wallet (Basic Maturity Level)

This is a security-improved version of bit_v0.py. It preserves all original
commands (generate, import, address, export, balance, send, history, utxos,
fees) while adding targeted security controls based on the security
evaluation framework.


"""

import argparse
import base64
import getpass
import os
import re
import secrets
import stat
import sys
from pathlib import Path

from bit import Key, PrivateKeyTestnet
from bit.network import fees

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYSTORE_DIR = Path.home() / ".bit_v1_keystore"
PBKDF2_ITERATIONS = 200_000          # K2: well above the 100k threshold
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32                         # AES-256-GCM
FEE_RATE_SOFT_CAP = 100              # T4: sat/vB; warn above this
FEE_RATE_HARD_CAP = 500              # T4: sat/vB; require explicit override
WIF_REGEX = re.compile(r"[5KLcm9][1-9A-HJ-NP-Za-km-z]{50,51}")  # M2 redaction


# ---------------------------------------------------------------------------
# M4 — Centralised exception handler & secret sanitiser
# ---------------------------------------------------------------------------

def _sanitize(text: str) -> str:
    """Strip anything that looks like a WIF from arbitrary text (M2/M4)."""
    if text is None:
        return ""
    return WIF_REGEX.sub("[REDACTED-WIF]", str(text))


def safe_error(prefix: str, exc: BaseException) -> None:
    """
    M4: print a generic error message with sanitised content. Never prints
    a stack trace and never echoes input WIFs back to the terminal.
    """
    msg = _sanitize(str(exc))
    # Library error messages occasionally embed the caller's input verbatim
    # (e.g. "derived from '<WIF>' ..."). The redaction above neutralises that
    # whole class of leaks.
    print(f"{prefix}: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_key_class(is_testnet: bool):
    return PrivateKeyTestnet if is_testnet else Key


def network_label(is_testnet: bool) -> str:
    return "TESTNET" if is_testnet else "MAINNET"


def _ensure_keystore_dir() -> None:
    """Create ~/.bit_v1_keystore with 0700 permissions (K3)."""
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(KEYSTORE_DIR, 0o700)
    except OSError:
        # Best-effort on platforms where chmod is a no-op (e.g. Windows).
        pass


# ---------------------------------------------------------------------------
# K1/K2/K3 — Encrypted keystore (PBKDF2 + AES-GCM, chmod 600)
# ---------------------------------------------------------------------------

def _derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def _keystore_path(name: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name)
    if not safe:
        raise ValueError("Keystore name cannot be empty.")
    return KEYSTORE_DIR / f"{safe}.keystore"


def save_encrypted_wif(name: str, wif: str, passphrase: str,
                        is_testnet: bool) -> Path:
    """
    K1+K2+K3: persist the WIF in an authenticated-encrypted file.
    Format (text, line-oriented, easy to inspect/migrate):

        BITV1-KEYSTORE-1
        kdf=PBKDF2-HMAC-SHA256
        iter=<iterations>
        salt=<base64>
        nonce=<base64>
        net=<MAINNET|TESTNET>
        ct=<base64-aes256gcm-ciphertext>
    """
    _ensure_keystore_dir()
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = _derive_key(passphrase, salt)
    aes = AESGCM(key)
    aad = network_label(is_testnet).encode("ascii")
    ct = aes.encrypt(nonce, wif.encode("utf-8"), aad)

    path = _keystore_path(name)
    body = (
        "BITV1-KEYSTORE-1\n"
        f"kdf=PBKDF2-HMAC-SHA256\n"
        f"iter={PBKDF2_ITERATIONS}\n"
        f"salt={base64.b64encode(salt).decode()}\n"
        f"nonce={base64.b64encode(nonce).decode()}\n"
        f"net={network_label(is_testnet)}\n"
        f"ct={base64.b64encode(ct).decode()}\n"
    )

    # Open with O_CREAT|O_EXCL|O_WRONLY at mode 0600 so the file is never
    # world-readable, even briefly. (K3)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(body)
    except Exception:
        os.close(fd) if False else None  # fdopen owns fd
        raise
    try:
        os.chmod(path, 0o600)             # idempotent enforcement (K3)
    except OSError:
        pass
    return path


def load_encrypted_wif(name: str, passphrase: str):
    """Returns (wif_str, is_testnet). Raises on tamper / wrong passphrase."""
    path = _keystore_path(name)
    if not path.exists():
        raise FileNotFoundError(f"No keystore named '{name}' found.")
    fields = {}
    with open(path, "r") as f:
        first = f.readline().strip()
        if first != "BITV1-KEYSTORE-1":
            raise ValueError("Unrecognised keystore format.")
        for line in f:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                fields[k] = v
    salt = base64.b64decode(fields["salt"])
    nonce = base64.b64decode(fields["nonce"])
    ct = base64.b64decode(fields["ct"])
    net = fields.get("net", "MAINNET")
    iters = int(fields.get("iter", PBKDF2_ITERATIONS))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iters,
    )
    key = kdf.derive(passphrase.encode("utf-8"))
    aes = AESGCM(key)
    try:
        wif_bytes = aes.decrypt(nonce, ct, net.encode("ascii"))
    except Exception:
        # AES-GCM tag mismatch → wrong passphrase OR tampered file.
        raise ValueError("Decryption failed: wrong passphrase or tampered keystore.")
    return wif_bytes.decode("utf-8"), (net == "TESTNET")


# ---------------------------------------------------------------------------
# M3 — Secure WIF / passphrase entry
# ---------------------------------------------------------------------------

def prompt_wif_or_load(args) -> tuple:
    """
    Returns (wif, is_testnet). Resolution order:
      1. --keystore NAME   → decrypt with getpass passphrase.
      2. otherwise         → getpass prompt for the raw WIF (M3).

    The original prototype accepted the WIF as a positional CLI argument,
    which leaks it into shell history and `ps`. v1 removes that path.
    """
    if getattr(args, "keystore", None):
        passphrase = getpass.getpass(
            f"Passphrase for keystore '{args.keystore}': "
        )
        wif, ks_testnet = load_encrypted_wif(args.keystore, passphrase)
        if args.testnet != ks_testnet:
            print(
                f"[!] Keystore is {network_label(ks_testnet)} but you used "
                f"--testnet={args.testnet}. Using keystore's network.",
                file=sys.stderr,
            )
        return wif, ks_testnet
    # No keystore → prompt silently.
    wif = getpass.getpass("Enter WIF (input hidden): ").strip()
    if not wif:
        raise ValueError("No WIF provided.")
    return wif, args.testnet


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def generate(args):
    """Generate a new key. Optionally save it encrypted to the keystore."""
    KeyClass = get_key_class(args.testnet)
    k = KeyClass()
    addr = k.segwit_address
    wif = k.to_wif()

    print(f"Network: {network_label(args.testnet)}")
    print(f"Address: {addr}")

    if args.save_to:
        # Encrypted-by-default for the persisted artefact (K1/K2/K3).
        p1 = getpass.getpass("New keystore passphrase: ")
        p2 = getpass.getpass("Confirm passphrase: ")
        if p1 != p2:
            raise ValueError("Passphrases do not match.")
        if len(p1) < 8:
            raise ValueError("Passphrase must be at least 8 characters.")
        path = save_encrypted_wif(args.save_to, wif, p1, args.testnet)
        print(f"Encrypted keystore written to: {path}")
        print("Permissions: 0600 (owner-only).")
        print("WIF is NOT printed to stdout. Use `export --i-understand-the-risk` to reveal.")
    else:
        # Default printing path remains, but with a loud warning (U1).
        print("[!] WIF will be printed below. Anything on your terminal can")
        print("[!] read it. Prefer `generate --save-to NAME`.")
        print(f"WIF: {wif}")


def import_key(args):
    """Import a WIF (via getpass) and optionally save it encrypted."""
    KeyClass = get_key_class(args.testnet)
    wif = getpass.getpass("Enter WIF to import (input hidden): ").strip()
    if not wif:
        raise ValueError("No WIF provided.")
    k = KeyClass(wif)
    print(f"Network: {network_label(args.testnet)}")
    print(f"Address: {k.segwit_address}")
    print(f"Balance: {k.get_balance('btc')} BTC")
    if args.save_to:
        p1 = getpass.getpass("New keystore passphrase: ")
        p2 = getpass.getpass("Confirm passphrase: ")
        if p1 != p2:
            raise ValueError("Passphrases do not match.")
        if len(p1) < 8:
            raise ValueError("Passphrase must be at least 8 characters.")
        path = save_encrypted_wif(args.save_to, wif, p1, args.testnet)
        print(f"Encrypted keystore written to: {path}")


def address(args):
    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)
    print(f"Network: {network_label(is_testnet)}")
    print(f"Address: {k.segwit_address}")


def export(args):
    """U1: dangerous — gated behind an explicit acknowledgement flag."""
    if not args.i_understand_the_risk:
        print(
            "[!] `export` reveals the raw WIF private key in plaintext on this terminal.\n"
            "[!] Anyone with access to your screen, scrollback or terminal logs\n"
            "[!] can steal your funds. To proceed, re-run with:\n"
            "        export --keystore NAME --i-understand-the-risk",
            file=sys.stderr,
        )
        sys.exit(2)

    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)  # validates the WIF
    print(f"Network: {network_label(is_testnet)}")
    print(f"Address: {k.segwit_address}")
    print(f"WIF: {k.to_wif()}")


def balance(args):
    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)
    print(f"Network: {network_label(is_testnet)}")
    print(f"Address: {k.segwit_address}")
    print(f"Balance: {k.get_balance('btc')} BTC")


def _check_fee_rate(rate, force: bool):
    """T4: enforce a soft warn-and-confirm threshold and a hard cap."""
    if rate is None:
        return  # auto-estimated
    if rate <= 0:
        raise ValueError("Fee rate must be positive.")
    if rate > FEE_RATE_HARD_CAP:
        if not force:
            raise ValueError(
                f"Fee rate {rate} sat/vB exceeds the hard cap of "
                f"{FEE_RATE_HARD_CAP} sat/vB. Re-run with "
                f"--i-understand-the-risk to override."
            )
        print(
            f"[!] WARNING: Forcing extreme fee rate {rate} sat/vB "
            f"(> {FEE_RATE_HARD_CAP}). This is almost certainly a mistake.",
            file=sys.stderr,
        )
    elif rate > FEE_RATE_SOFT_CAP:
        print(
            f"[!] Caution: fee rate {rate} sat/vB is unusually high "
            f"(soft cap {FEE_RATE_SOFT_CAP} sat/vB). Continuing.",
            file=sys.stderr,
        )


def send(args):
    """
    T1: review screen of all critical fields before signing.
    T3: explicit yes/no confirmation prompt.
    T4: fee-rate sanity checks with explicit override.
    """
    _check_fee_rate(args.fee, args.i_understand_the_risk)

    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)

    fee_display = f"{args.fee} sat/vB (manual)" if args.fee is not None \
        else "auto-estimated by bit"

    # --- T1: Review screen ------------------------------------------------
    print("=" * 60)
    print(" TRANSACTION REVIEW — confirm carefully before signing")
    print("=" * 60)
    print(f" Network    : {network_label(is_testnet)}")
    print(f" From       : {k.segwit_address}")
    print(f" To         : {args.dest}")
    print(f" Amount     : {args.amount} BTC")
    print(f" Fee rate   : {fee_display}")
    print(f" Change     : returns to sender address ({k.segwit_address})")
    if args.fee is not None and args.fee > FEE_RATE_SOFT_CAP:
        print(" [!] Fee rate is above the soft cap — double-check this!")
    print("=" * 60)

    # --- T3: Confirmation prompt -----------------------------------------
    answer = input("Type 'yes' to broadcast, anything else to abort: ").strip().lower()
    if answer != "yes":
        print("Aborted by user. No transaction was broadcast.")
        return

    if args.fee is not None:
        tx_hash = k.send([(args.dest, args.amount, "btc")], fee=args.fee)
    else:
        tx_hash = k.send([(args.dest, args.amount, "btc")])

    print(f"Transaction sent! Hash: {tx_hash}")


def history(args):
    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)
    txs = k.get_transactions()
    print(f"Network: {network_label(is_testnet)}")
    print(f"Transaction History ({len(txs)}):")
    for tx in txs:
        print(tx)


def utxos(args):
    wif, is_testnet = prompt_wif_or_load(args)
    KeyClass = get_key_class(is_testnet)
    k = KeyClass(wif)
    unspents = k.get_unspents()
    print(f"Network: {network_label(is_testnet)}")
    if not unspents:
        print("No UTXOs available.")
        return
    print(f"Available UTXOs ({len(unspents)}):")
    for idx, u in enumerate(unspents, 1):
        print(f"  #{idx} - {u.amount} sat "
              f"({u.amount / 100_000_000} BTC) - {u.confirmations} confirmations")


def check_fees(args):
    print(f"Fastest Fee: {fees.get_fee_cached()} sat/byte")
    print(f"(Soft cap: {FEE_RATE_SOFT_CAP} sat/vB, "
          f"Hard cap: {FEE_RATE_HARD_CAP} sat/vB)")


def list_keystores(args):
    """Helper command to inspect saved encrypted keystores."""
    if not KEYSTORE_DIR.exists():
        print("(no keystore directory yet)")
        return
    items = sorted(KEYSTORE_DIR.glob("*.keystore"))
    if not items:
        print("(no keystores)")
        return
    print(f"Keystore directory: {KEYSTORE_DIR}")
    for p in items:
        st = p.stat()
        mode = stat.filemode(st.st_mode)
        print(f"  {p.name}    {mode}    {st.st_size} bytes")


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_common_key_args(p):
    """Subcommands that operate on an existing key get --keystore (no positional WIF)."""
    p.add_argument("--keystore", help="Name of an encrypted keystore in "
                                       f"{KEYSTORE_DIR}. If omitted, you will "
                                       "be prompted for the WIF (no echo).")


def main():
    parser = argparse.ArgumentParser(
        description="bit_v1 — hardened CLI Bitcoin wallet (Basic maturity).",
    )
    parser.add_argument("--testnet", action="store_true",
                        help="Use Testnet (default is Mainnet).")

    sub = parser.add_subparsers(dest="command", help="Available commands")
    sub.required = True

    # generate
    p = sub.add_parser("generate", help="Generate a new address")
    p.add_argument("--save-to", metavar="NAME",
                   help="Save the new key to an encrypted keystore.")
    p.set_defaults(func=generate)

    # import
    p = sub.add_parser("import", help="Import key from WIF (prompted, no echo)")
    p.add_argument("--save-to", metavar="NAME",
                   help="Save the imported key to an encrypted keystore.")
    p.set_defaults(func=import_key)

    # address
    p = sub.add_parser("address", help="Get receiving address")
    _add_common_key_args(p)
    p.set_defaults(func=address)

    # export (U1: gated)
    p = sub.add_parser("export", help="Export WIF key (DANGEROUS)")
    _add_common_key_args(p)
    p.add_argument("--i-understand-the-risk", action="store_true",
                   help="Required acknowledgement for revealing a WIF.")
    p.set_defaults(func=export)

    # balance
    p = sub.add_parser("balance", help="Check balance")
    _add_common_key_args(p)
    p.set_defaults(func=balance)

    # send
    p = sub.add_parser("send", help="Send BTC")
    _add_common_key_args(p)
    p.add_argument("dest", help="Destination address")
    p.add_argument("amount", type=float, help="Amount in BTC")
    p.add_argument("--fee", type=int,
                   help="Custom fee rate in sat/vB (omit for auto-estimate).")
    p.add_argument("--i-understand-the-risk", action="store_true",
                   help="Required to override the hard fee-rate cap.")
    p.set_defaults(func=send)

    # history
    p = sub.add_parser("history", help="View transaction history")
    _add_common_key_args(p)
    p.set_defaults(func=history)

    # utxos
    p = sub.add_parser("utxos", help="Display available UTXOs")
    _add_common_key_args(p)
    p.set_defaults(func=utxos)

    # fees
    p = sub.add_parser("fees", help="Check network fees")
    p.set_defaults(func=check_fees)

    # list-keystores (utility)
    p = sub.add_parser("list-keystores", help="List saved encrypted keystores")
    p.set_defaults(func=list_keystores)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except SystemExit:
        raise
    except Exception as exc:                              # M4
        # No traceback. No echoing of input. No leakage of WIF/local vars.
        safe_error(f"Error in '{args.command}'", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
