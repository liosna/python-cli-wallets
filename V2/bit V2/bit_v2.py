import argparse
import base64
import getpass
import json
import os
import re
import secrets
import stat
import subprocess  # nosec B404 — used only with a fixed argv list, no shell, no user data
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

KEYSTORE_DIR       = Path.home() / ".bit_v2_keystore"
POLICY_FILE        = Path.home() / ".bit_v2_policy.json"
PBKDF2_ITERATIONS  = 200_000         # K2: well above the 100k threshold
SALT_LEN           = 16
NONCE_LEN          = 12
KEY_LEN            = 32              # AES-256-GCM
FEE_RATE_SOFT_CAP  = 100             # T4: sat/vB — warn above this
FEE_RATE_HARD_CAP  = 500             # T4: sat/vB — block without --force-high-fee
WIF_REGEX          = re.compile(r"[5KLcm9][1-9A-HJ-NP-Za-km-z]{50,51}")

# Default policy (applied when no policy file exists yet)
_DEFAULT_POLICY: dict = {
    "version": 1,
    "spend_limit_btc": 0.0,                    # 0 = unlimited
    "allowlist": [],                            # [] = any address allowed
    "require_address_challenge_above_btc": 0.0, # 0 = disabled
}


# ---------------------------------------------------------------------------
# M4 — Centralised exception handler and secret sanitiser
# ---------------------------------------------------------------------------

def _sanitize(text: str) -> str:
    """Strip anything that looks like a WIF from arbitrary text (M2/M4)."""
    if text is None:
        return ""
    return WIF_REGEX.sub("[REDACTED-WIF]", str(text))


def safe_error(prefix: str, exc: BaseException) -> None:
    """M4: generic error, sanitised, no traceback, no key leakage."""
    print(f"{prefix}: {_sanitize(str(exc))}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def get_key_class(is_testnet: bool):
    """Return the appropriate bit Key class for the selected network."""
    return PrivateKeyTestnet if is_testnet else Key


def network_label(is_testnet: bool) -> str:
    """Return a human-readable network name for display and AAD binding."""
    return "TESTNET" if is_testnet else "MAINNET"


def _ensure_dir(path: Path, mode: int = 0o700) -> None:
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# K1/K2/K3 — Encrypted keystore (PBKDF2-HMAC-SHA256 + AES-256-GCM, 0600)
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
    K1+K2+K3: persist WIF in an authenticated-encrypted file.

    Format (text, line-oriented):
        BITV2-KEYSTORE-1
        kdf=PBKDF2-HMAC-SHA256
        iter=<n>
        salt=<base64>
        nonce=<base64>
        net=<MAINNET|TESTNET>
        ct=<base64-aes256gcm-ciphertext+tag>
    """
    _ensure_dir(KEYSTORE_DIR)
    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key   = _derive_key(passphrase, salt)
    aes   = AESGCM(key)
    aad   = network_label(is_testnet).encode("ascii")
    ct    = aes.encrypt(nonce, wif.encode("utf-8"), aad)
    del key

    path = _keystore_path(name)
    body = (
        "BITV2-KEYSTORE-1\n"
        f"kdf=PBKDF2-HMAC-SHA256\n"
        f"iter={PBKDF2_ITERATIONS}\n"
        f"salt={base64.b64encode(salt).decode()}\n"
        f"nonce={base64.b64encode(nonce).decode()}\n"
        f"net={network_label(is_testnet)}\n"
        f"ct={base64.b64encode(ct).decode()}\n"
    )

    # Open with O_CREAT|O_TRUNC|O_WRONLY at mode 0600 so the file is never
    # world-readable, even briefly. (K3)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    try:
        os.chmod(path, 0o600)    # idempotent re-enforcement (K3)
    except OSError:
        pass
    return path


def load_encrypted_wif(name: str, passphrase: str):
    """
    Returns (wif_str, is_testnet). Raises on tamper / wrong passphrase.
    Accepts both BITV1-KEYSTORE-1 and BITV2-KEYSTORE-1 headers for
    backwards compatibility with keystores created by bit_v1.
    """
    path = _keystore_path(name)
    if not path.exists():
        raise FileNotFoundError(
            f"No keystore named '{name}' found in {KEYSTORE_DIR}."
        )
    fields: dict = {}
    with open(path, "r", encoding="utf-8") as fh:
        first = fh.readline().strip()
        if first not in ("BITV2-KEYSTORE-1", "BITV1-KEYSTORE-1"):
            raise ValueError("Unrecognised keystore format.")
        for line in fh:
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                fields[k] = v

    salt  = base64.b64decode(fields["salt"])
    nonce = base64.b64decode(fields["nonce"])
    ct    = base64.b64decode(fields["ct"])
    net   = fields.get("net", "MAINNET")
    iters = int(fields.get("iter", PBKDF2_ITERATIONS))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=iters,
    )
    raw_key = kdf.derive(passphrase.encode("utf-8"))
    aes = AESGCM(raw_key)
    del raw_key
    try:
        wif_bytes = aes.decrypt(nonce, ct, net.encode("ascii"))
    except Exception as exc:
        raise ValueError(
            "Decryption failed: wrong passphrase or tampered keystore."
        ) from exc
    return wif_bytes.decode("utf-8"), (net == "TESTNET")


# ---------------------------------------------------------------------------
# M3 — Secure key loading (keystore-only; no raw-WIF CLI fallback)
# ---------------------------------------------------------------------------

def load_key_from_keystore(args):
    """
    M3+K1: ALL key operations go through the encrypted keystore. There is
    no raw-WIF prompt fallback. Returns (wif, is_testnet).
    """
    if not getattr(args, "keystore", None):
        raise ValueError(
            "A --keystore NAME is required. "
            "Create one with `generate --name NAME` or `import --name NAME`."
        )
    passphrase = getpass.getpass(f"Passphrase for keystore '{args.keystore}': ")
    try:
        wif, is_testnet = load_encrypted_wif(args.keystore, passphrase)
    finally:
        del passphrase   # M1: best-effort cleanup
    return wif, is_testnet


def _prompt_new_passphrase() -> str:
    """Prompt for a new passphrase with confirmation and minimum-length guard."""
    p1 = getpass.getpass("New keystore passphrase: ")
    p2 = getpass.getpass("Confirm passphrase: ")
    if p1 != p2:
        del p1, p2
        raise ValueError("Passphrases do not match.")
    if len(p1) < 8:
        del p1, p2
        raise ValueError("Passphrase must be at least 8 characters.")
    del p2
    return p1


# ---------------------------------------------------------------------------
# T3 — Policy engine (spend cap, address allowlist, address challenge)
# ---------------------------------------------------------------------------

def _load_policy() -> dict:
    if not POLICY_FILE.exists():
        return dict(_DEFAULT_POLICY)
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as fh:
            policy = json.load(fh)
        for k, v in _DEFAULT_POLICY.items():
            policy.setdefault(k, v)
        return policy
    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Cannot read policy file ({exc}); using defaults.", file=sys.stderr)
        return dict(_DEFAULT_POLICY)


def _save_policy(policy: dict) -> None:
    _ensure_dir(POLICY_FILE.parent)
    tmp = POLICY_FILE.with_suffix(".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2)
    os.replace(tmp, POLICY_FILE)
    try:
        os.chmod(POLICY_FILE, 0o600)
    except OSError:
        pass


def _enforce_policy(policy: dict, dest: str, amount_btc: float) -> None:
    """
    T3: enforce spend limit and address allowlist before transaction is built.
    Raises ValueError on policy violation; the transaction is never constructed.
    """
    spend_limit = float(policy.get("spend_limit_btc", 0.0))
    if spend_limit > 0 and amount_btc > spend_limit:
        raise ValueError(
            f"Policy violation: amount {amount_btc} BTC exceeds the spend "
            f"limit of {spend_limit} BTC. Adjust with `set-policy`."
        )
    allowlist = policy.get("allowlist", [])
    if allowlist and dest not in allowlist:
        raise ValueError(
            f"Policy violation: destination '{dest}' is not in the address "
            f"allowlist. Add it with `set-policy` or clear the allowlist."
        )


def _address_challenge(dest: str) -> None:
    """
    T3: clipboard-hijacking guard for high-value sends.
    Forces the user to visually verify and type the last 8 characters
    of the destination address before signing proceeds.
    """
    tail = dest[-8:]
    print()
    print("[!] HIGH-VALUE SEND — address confirmation required.")
    print(f"    Full destination : {dest}")
    print("    Type the LAST 8 characters to confirm: ", end="", flush=True)
    entered = input().strip()
    if entered != tail:
        raise ValueError(
            f"Address confirmation failed (expected '{tail}'). "
            "Transaction aborted to prevent potential clipboard-hijacking."
        )


def _print_policy(policy: dict) -> None:
    sl = float(policy.get("spend_limit_btc", 0))
    al = policy.get("allowlist", [])
    dc = float(policy.get("require_address_challenge_above_btc", 0))
    print("Current transaction policy:")
    print(f"  Spend limit per transaction : {'unlimited' if not sl else f'{sl} BTC'}")
    print(f"  Address allowlist           : {'any address' if not al else ', '.join(al)}")
    print(f"  Address challenge above     : {'disabled' if not dc else f'{dc} BTC'}")


# ---------------------------------------------------------------------------
# T4 — Fee safeguards with dedicated --force-high-fee override
# ---------------------------------------------------------------------------

def _check_fee_rate(rate, force_high_fee: bool) -> None:
    """T4: soft-warn threshold + enforceable hard cap."""
    if rate is None:
        return
    if rate <= 0:
        raise ValueError("Fee rate must be a positive integer (sat/vB).")
    if rate > FEE_RATE_HARD_CAP:
        if not force_high_fee:
            raise ValueError(
                f"Fee rate {rate} sat/vB exceeds the hard cap of "
                f"{FEE_RATE_HARD_CAP} sat/vB. Add --force-high-fee to override."
            )
        print(
            f"[!] WARNING: forcing extreme fee rate {rate} sat/vB "
            f"(> {FEE_RATE_HARD_CAP}). Verify this is intentional.",
            file=sys.stderr,
        )
    elif rate > FEE_RATE_SOFT_CAP:
        print(
            f"[!] Caution: fee rate {rate} sat/vB is unusually high "
            f"(soft cap {FEE_RATE_SOFT_CAP} sat/vB). Continuing.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def generate(args):
    """
    K1/M2/U1: ALWAYS saves to an encrypted keystore. WIF is never printed
    to stdout in the normal workflow.
    """
    KeyClass = get_key_class(args.testnet)
    k    = KeyClass()
    addr = k.segwit_address
    wif  = k.to_wif()

    passphrase = _prompt_new_passphrase()
    try:
        path = save_encrypted_wif(args.name, wif, passphrase, args.testnet)
    finally:
        del passphrase
        del wif          # M1: best-effort cleanup

    print(f"Network  : {network_label(args.testnet)}")
    print(f"Address  : {addr}")
    print(f"Keystore : {path}")
    print(f"Mode     : AES-256-GCM / PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} iterations)")
    print("WIF is NOT printed. Use `export --keystore NAME --i-understand-the-risk` to reveal.")


def import_key(args):
    """
    M3: WIF entered via getpass (no echo, no CLI arg).
    K1: immediately saved to the encrypted keystore; never stored in plaintext.
    """
    KeyClass = get_key_class(args.testnet)
    wif = getpass.getpass("Enter WIF to import (input hidden): ").strip()
    if not wif:
        raise ValueError("No WIF provided.")
    try:
        k    = KeyClass(wif)
        addr = k.segwit_address

        passphrase = _prompt_new_passphrase()
        try:
            path = save_encrypted_wif(args.name, wif, passphrase, args.testnet)
        finally:
            del passphrase
    finally:
        del wif          # M1: best-effort cleanup

    print(f"Network  : {network_label(args.testnet)}")
    print(f"Address  : {addr}")
    print(f"Keystore : {path}")


def address(args):
    """Show the receiving address derived from the keystore."""
    wif, is_testnet = load_key_from_keystore(args)
    try:
        k = get_key_class(is_testnet)(wif)
        print(f"Network : {network_label(is_testnet)}")
        print(f"Address : {k.segwit_address}")
    finally:
        del wif


def export(args):
    """U1: gated behind an explicit acknowledgement flag."""
    if not args.i_understand_the_risk:
        print(
            "[!] `export` reveals the raw WIF private key in plaintext on this terminal.\n"
            "[!] Anyone with access to your screen, scrollback, or terminal logs\n"
            "[!] can steal your funds. To proceed, re-run with:\n"
            "        export --keystore NAME --i-understand-the-risk",
            file=sys.stderr,
        )
        sys.exit(2)

    wif, is_testnet = load_key_from_keystore(args)
    k = get_key_class(is_testnet)(wif)
    # Intentional WIF reveal — user passed --i-understand-the-risk.
    print(f"Network : {network_label(is_testnet)}")
    print(f"Address : {k.segwit_address}")
    print(f"WIF     : {k.to_wif()}")


def balance(args):
    """Display the current confirmed balance for the wallet."""
    wif, is_testnet = load_key_from_keystore(args)
    try:
        k = get_key_class(is_testnet)(wif)
        print(f"Network : {network_label(is_testnet)}")
        print(f"Address : {k.segwit_address}")
        print(f"Balance : {k.get_balance('btc')} BTC")
    finally:
        del wif


def send(args):
    """
    T1: comprehensive review screen before signing.
    T3: policy enforcement (spend cap + allowlist + address challenge).
    T3: mandatory yes/no confirmation prompt.
    T4: fee safeguards with dedicated --force-high-fee override.
    """
    _check_fee_rate(args.fee, args.force_high_fee)   # T4: fail fast before loading key

    policy = _load_policy()
    _enforce_policy(policy, args.dest, args.amount)  # T3: policy check before loading key

    wif, is_testnet = load_key_from_keystore(args)
    try:
        k = get_key_class(is_testnet)(wif)
        fee_display = (f"{args.fee} sat/vB (manual)" if args.fee is not None
                       else "auto-estimated by bit")

        # --- T1: Review screen ---
        print("=" * 64)
        print("  TRANSACTION REVIEW — confirm carefully before signing")
        print("=" * 64)
        print(f"  Network    : {network_label(is_testnet)}")
        print(f"  From       : {k.segwit_address}")
        print(f"  To         : {args.dest}")
        print(f"  Amount     : {args.amount} BTC")
        print(f"  Fee rate   : {fee_display}")
        print(f"  Change     : returns to {k.segwit_address}")
        spend_lim = float(policy.get("spend_limit_btc", 0))
        if spend_lim > 0:
            print(f"  Policy cap : {spend_lim} BTC per transaction")
        if args.fee is not None and args.fee > FEE_RATE_SOFT_CAP:
            print(f"  [!] Fee rate above soft cap ({FEE_RATE_SOFT_CAP} sat/vB)!")
        print("=" * 64)

        # --- T3: Address challenge for high-value sends ---
        challenge_threshold = float(
            policy.get("require_address_challenge_above_btc", 0)
        )
        if challenge_threshold > 0 and args.amount > challenge_threshold:
            _address_challenge(args.dest)

        # --- T3: Mandatory confirmation prompt ---
        answer = input("Type 'yes' to broadcast, anything else to abort: ").strip().lower()
        if answer != "yes":
            print("Aborted by user. No transaction was broadcast.")
            return

        if args.fee is not None:
            tx_hash = k.send([(args.dest, args.amount, "btc")], fee=args.fee)
        else:
            tx_hash = k.send([(args.dest, args.amount, "btc")])

        print(f"Transaction sent! Hash: {tx_hash}")
    finally:
        del wif


def history(args):
    """List confirmed transactions for the wallet address."""
    wif, is_testnet = load_key_from_keystore(args)
    try:
        k   = get_key_class(is_testnet)(wif)
        txs = k.get_transactions()
        print(f"Network: {network_label(is_testnet)}")
        print(f"Transaction history ({len(txs)}):")
        for tx in txs:
            print(tx)
    finally:
        del wif


def utxos(args):
    """List unspent transaction outputs (UTXOs) for the wallet."""
    wif, is_testnet = load_key_from_keystore(args)
    try:
        k        = get_key_class(is_testnet)(wif)
        unspents = k.get_unspents()
        print(f"Network: {network_label(is_testnet)}")
        if not unspents:
            print("No UTXOs available.")
            return
        print(f"Available UTXOs ({len(unspents)}):")
        for idx, u in enumerate(unspents, 1):
            print(f"  #{idx}  {u.amount} sat "
                  f"({u.amount / 100_000_000:.8f} BTC)  "
                  f"{u.confirmations} confirmations")
    finally:
        del wif


def check_fees(_args):
    """Display current network fee estimate and the configured policy caps."""
    print(f"Fastest fee  : {fees.get_fee_cached()} sat/byte")
    print(f"Soft cap     : {FEE_RATE_SOFT_CAP} sat/vB  (warning only)")
    print(
        f"Hard cap     : {FEE_RATE_HARD_CAP} sat/vB"
        "  (enforced; override: --force-high-fee on send)"
    )


def list_keystores(_args):
    """Show all encrypted keystores in KEYSTORE_DIR with their permissions."""
    if not KEYSTORE_DIR.exists():
        print("(no keystore directory yet)")
        return
    items = sorted(KEYSTORE_DIR.glob("*.keystore"))
    if not items:
        print("(no keystores found)")
        return
    print(f"Keystore directory: {KEYSTORE_DIR}")
    for p in items:
        st   = p.stat()
        mode = stat.filemode(st.st_mode)
        print(f"  {p.name:<30}  {mode}  {st.st_size} bytes")


def set_policy(args):
    """T3: create or update the JSON policy file."""
    policy = _load_policy()
    print("Configure transaction policy. Press Enter to keep the current value.")

    current_sl = policy["spend_limit_btc"]
    print(f"  Spend limit in BTC (0 = unlimited) [{current_sl}]: ", end="")
    raw = input().strip()
    if raw:
        policy["spend_limit_btc"] = float(raw)

    current_al = ",".join(policy["allowlist"]) if policy["allowlist"] else "(any)"
    print(f"  Address allowlist, comma-separated (empty/'clear' = any) [{current_al}]: ", end="")
    raw = input().strip()
    if raw in ("clear", "none", "-"):
        policy["allowlist"] = []
    elif raw:
        policy["allowlist"] = [a.strip() for a in raw.split(",") if a.strip()]

    current_dc = policy["require_address_challenge_above_btc"]
    print(f"  Address-challenge threshold in BTC (0 = disabled) [{current_dc}]: ", end="")
    raw = input().strip()
    if raw:
        policy["require_address_challenge_above_btc"] = float(raw)

    _save_policy(policy)
    print(f"\nPolicy saved to {POLICY_FILE}  (mode 0600)")
    _print_policy(policy)


def show_policy(_args):
    """Display the current transaction policy."""
    _print_policy(_load_policy())


def check_deps(_args):
    """
    D2: run pip-audit to check for known vulnerabilities in the dependency
    tree. pip-audit must be installed: pip install pip-audit
    """
    try:
        result = subprocess.run(  # nosec B603 — fixed argv, no shell, no user data
            [sys.executable, "-m", "pip_audit", "--strict"],
            check=False,
        )
        if result.returncode != 0:
            print(
                "[!] pip-audit reported vulnerabilities. Review the output above.",
                file=sys.stderr,
            )
            sys.exit(result.returncode)
        else:
            print("[+] pip-audit: no known vulnerabilities found.")
    except FileNotFoundError:
        print(
            "[!] pip-audit is not installed. Enable dependency scanning with:\n"
            "        pip install pip-audit\n"
            "    Then re-run:  python bit_v2.py check-deps",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_keystore_arg(p) -> None:
    """Operational subcommands all require --keystore (no raw-WIF fallback)."""
    p.add_argument(
        "--keystore", required=True, metavar="NAME",
        help=f"Encrypted keystore name in {KEYSTORE_DIR}.",
    )


def main():
    parser = argparse.ArgumentParser(
        description="bit_v2 — Moderate maturity CLI Bitcoin wallet.",
    )
    parser.add_argument("--testnet", action="store_true",
                        help="Use Testnet (default: Mainnet).")

    sub = parser.add_subparsers(dest="command", help="Available commands")
    sub.required = True

    # generate — K1/U1: --name required; always saves encrypted; no WIF print
    p = sub.add_parser("generate", help="Generate a new key and save to encrypted keystore")
    p.add_argument("--name", required=True, metavar="NAME",
                   help="Keystore name for the new key.")
    p.set_defaults(func=generate)

    # import — M3: WIF via getpass only; --name required
    p = sub.add_parser("import", help="Import WIF (prompted, no echo) → encrypted keystore")
    p.add_argument("--name", required=True, metavar="NAME",
                   help="Keystore name for the imported key.")
    p.set_defaults(func=import_key)

    # address
    p = sub.add_parser("address", help="Get receiving address")
    _add_keystore_arg(p)
    p.set_defaults(func=address)

    # export — U1: gated
    p = sub.add_parser("export", help="Export WIF key (DANGEROUS)")
    _add_keystore_arg(p)
    p.add_argument("--i-understand-the-risk", action="store_true",
                   help="Required acknowledgement for revealing a WIF.")
    p.set_defaults(func=export)

    # balance
    p = sub.add_parser("balance", help="Check balance")
    _add_keystore_arg(p)
    p.set_defaults(func=balance)

    # send — T1/T3/T4
    p = sub.add_parser("send", help="Send BTC")
    _add_keystore_arg(p)
    p.add_argument("dest",   help="Destination Bitcoin address")
    p.add_argument("amount", type=float, help="Amount in BTC")
    p.add_argument("--fee", type=int,
                   help="Custom fee rate in sat/vB (omit for auto-estimate).")
    p.add_argument("--force-high-fee", action="store_true",
                   help="Override the fee hard cap (T4). Use with extreme caution.")
    p.set_defaults(func=send)

    # history
    p = sub.add_parser("history", help="View transaction history")
    _add_keystore_arg(p)
    p.set_defaults(func=history)

    # utxos
    p = sub.add_parser("utxos", help="Display available UTXOs")
    _add_keystore_arg(p)
    p.set_defaults(func=utxos)

    # fees
    p = sub.add_parser("fees", help="Check network fee rates and policy caps")
    p.set_defaults(func=check_fees)

    # list-keystores
    p = sub.add_parser("list-keystores", help="List saved encrypted keystores")
    p.set_defaults(func=list_keystores)

    # set-policy — T3
    p = sub.add_parser("set-policy",
                       help="Configure spend limits and address allowlist (T3)")
    p.set_defaults(func=set_policy)

    # show-policy
    p = sub.add_parser("show-policy", help="Display current transaction policy")
    p.set_defaults(func=show_policy)

    # check-deps — D2
    p = sub.add_parser("check-deps",
                       help="Scan dependencies for known vulnerabilities (requires pip-audit)")
    p.set_defaults(func=check_deps)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:  # M4: intercept all errors to prevent WIF leakage in tracebacks
        safe_error(f"Error in '{args.command}'", exc)
        sys.exit(1)
    # SystemExit and KeyboardInterrupt (BaseException, not Exception) propagate naturally.


if __name__ == "__main__":
    main()
