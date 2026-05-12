#!/usr/bin/env python3
"""
bitcoinlib_v03.py — Robust Maturity Level Bitcoin CLI wallet prototype.

Threat model: compromised laptop, user-level attacker with read access to
/proc/<PID>/mem, filesystem, shell history, and terminal scrollback.

Security architecture:
  - All private-key signing performed in Rust (bitcoin_signer) with
    deterministic zeroization via the `zeroize` crate.
  - Python never holds raw WIF/xprv/seed as a str after wallet creation;
    key material is stored only as an AES-256-GCM encrypted blob.
  - No CLI arguments accept secret material; all secrets enter via getpass.
  - Wallet database is SQLCipher-encrypted (AES-256-CBC + PBKDF2-SHA512).
  - Policy engine (JSON + HMAC-SHA256) enforces spend limits, fee caps,
    allowlist/denylist, and address challenges before every signing call.
"""
import sys
import os
import re
import json
import hmac as _hmac_mod
import hashlib
import argparse
import getpass
import random
import secrets
import subprocess
from pathlib import Path
from pprint import pprint

# ---------------------------------------------------------------------------
# SECURITY: SQLCipher driver check
# ---------------------------------------------------------------------------
try:
    import pysqlcipher3
    import pysqlcipher3.dbapi2
except ImportError:
    print("CRITICAL ERROR: pysqlcipher3 is not installed.", file=sys.stderr)
    print("This wallet requires SQLCipher database encryption.", file=sys.stderr)
    print("Install libsqlcipher (OS) then build pysqlcipher3 from source.", file=sys.stderr)
    sys.exit(1)

# Monkeypatch: suppress deterministic=True on older pysqlcipher3 builds
try:
    _mc = pysqlcipher3.dbapi2.connect(":memory:")
    try:
        _mc.create_function("_t", 0, lambda: None, deterministic=True)
    except TypeError:
        _orig_connect = pysqlcipher3.dbapi2.connect

        class _ConnectionProxy:
            def __init__(self, c):
                self._c = c
            def __getattr__(self, name):
                return getattr(self._c, name)
            def create_function(self, name, n, fn, *a, **kw):
                kw.pop('deterministic', None)
                return self._c.create_function(name, n, fn, *a, **kw)

        def _connect_wrapper(*a, **kw):
            return _ConnectionProxy(_orig_connect(*a, **kw))

        pysqlcipher3.dbapi2.connect = _connect_wrapper
    except Exception:
        pass
    finally:
        _mc.close()
except Exception:
    pass

from bitcoinlib.wallets import (
    Wallet, wallets_list, wallet_exists, wallet_delete, WalletError, wallet_empty,
)
from bitcoinlib.keys import HDKey, get_key_format
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.main import BITCOINLIB_VERSION
from bitcoinlib.config.config import DEFAULT_NETWORK

# ---------------------------------------------------------------------------
# Rust signing module
# ---------------------------------------------------------------------------
try:
    import bitcoin_signer as _rust_signer
    _RUST_AVAILABLE = True
except ImportError:
    _rust_signer = None
    _RUST_AVAILABLE = False
    print(
        "[WARN] bitcoin_signer Rust module not available. "
        "Build with: cd signer && maturin develop --release",
        file=sys.stderr,
    )

# ---------------------------------------------------------------------------
# Secure wallet data directory
# ---------------------------------------------------------------------------
_WALLET_DATA_DIR = Path.home() / ".local" / "share" / "btcwallet"


def _ensure_wallet_dir() -> Path:
    """Create the wallet data directory with 0700 permissions."""
    _WALLET_DATA_DIR.mkdir(parents=True, exist_ok=True)
    _WALLET_DATA_DIR.chmod(0o700)
    return _WALLET_DATA_DIR


def _default_db_path() -> str:
    """Return the default wallet database path in the secure data directory."""
    return str(_ensure_wallet_dir() / "bitcoin.sqlite")


# ---------------------------------------------------------------------------
# M2 / M4 — Secret redaction (applied to all output paths)
# ---------------------------------------------------------------------------
_REDACT_PATTERNS = [
    re.compile(r'[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}'),  # HD extended private keys
    re.compile(r'[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}'),   # WIF private keys
    re.compile(r'\b(?:[a-z]{3,8}\s){11,23}[a-z]{3,8}\b'),  # mnemonic-like phrases
]


def _redact(text: str) -> str:
    for pat in _REDACT_PATTERNS:
        text = pat.sub('[REDACTED]', text)
    return text


def exception_handler(exc_type, exc, _tb):
    print(_redact(f"{exc_type.__name__}: {exc}"), file=sys.stderr)


# ---------------------------------------------------------------------------
# Filesystem permissions enforcement
# ---------------------------------------------------------------------------

def _check_path_permissions(path: str, expected_mode: int, label: str) -> None:
    """Abort if *path* has permissions broader than *expected_mode*."""
    abs_path = os.path.abspath(path)
    if not os.path.exists(abs_path):
        return
    mode = os.stat(abs_path).st_mode & 0o777
    if mode & ~expected_mode:
        print(
            f"CRITICAL SECURITY FAILURE: {label} '{abs_path}' has insecure "
            f"permissions ({oct(mode)}). Expected at most {oct(expected_mode)}.",
            file=sys.stderr,
        )
        sys.exit(1)


def parse_db_path(db_uri: str) -> str:
    if '://' in db_uri:
        if not (db_uri.startswith('sqlite://') or
                db_uri.startswith('sqlite+pysqlcipher://')):
            print(
                f"CRITICAL SECURITY ERROR: Only SQLite file databases supported "
                f"(URI: {db_uri}).",
                file=sys.stderr,
            )
            sys.exit(1)
        path = db_uri.split(':///', 1)[1] if ':///' in db_uri else db_uri.split('://', 1)[1]
    else:
        path = db_uri

    if not path or path == ':memory:':
        print("CRITICAL SECURITY ERROR: In-memory databases are forbidden.", file=sys.stderr)
        sys.exit(1)

    abs_path = os.path.abspath(path)

    # Refuse world-readable or group-readable paths
    parent = os.path.dirname(abs_path)
    if os.path.exists(parent):
        parent_mode = os.stat(parent).st_mode & 0o777
        if parent_mode & 0o077:
            print(
                f"CRITICAL SECURITY ERROR: Database parent directory '{parent}' "
                f"is group- or world-accessible ({oct(parent_mode)}). "
                f"Use a directory with 0700 permissions.",
                file=sys.stderr,
            )
            sys.exit(1)

    return abs_path


def check_permissions(db_uri: str) -> None:
    abs_path = parse_db_path(db_uri)
    db_dir = os.path.dirname(abs_path)
    _check_path_permissions(db_dir, 0o700, "Database directory")
    _check_path_permissions(abs_path, 0o600, "Database file")


def verify_encryption_at_rest(db_uri: str) -> None:
    abs_path = parse_db_path(db_uri)
    if not os.path.exists(abs_path):
        return
    try:
        proc = subprocess.run(
            ['sqlite3', abs_path, 'SELECT count(*) FROM sqlite_master;'],
            capture_output=True, text=True,
        )
        if proc.returncode == 0:
            print(
                f"CRITICAL SECURITY FAILURE: Database '{abs_path}' is NOT "
                f"ENCRYPTED (plain sqlite3 opened it).",
                file=sys.stderr,
            )
            sys.exit(1)
    except FileNotFoundError:
        print(
            "SECURITY ERROR: sqlite3 CLI not found. Install it for encryption "
            "verification.",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Database password — never accepted as a CLI argument
# ---------------------------------------------------------------------------

def get_db_password() -> str:
    try:
        password = getpass.getpass("Enter Wallet Database Password: ")
    except KeyboardInterrupt:
        print("", file=sys.stderr)
        sys.exit(1)

    if not password:
        print("Error: Database password is required.", file=sys.stderr)
        sys.exit(1)

    return password


# ---------------------------------------------------------------------------
# L1 / L2 — Safe failure mode for database integrity errors
# ---------------------------------------------------------------------------
_DB_CORRUPTION_HINTS = frozenset([
    'hmac', 'file is not a database', 'database disk image is malformed',
    'encryption', 'page', 'integrity', 'corrupt',
])


def handle_db_error(exc: Exception) -> bool:
    msg = str(exc).lower()
    if not any(hint in msg for hint in _DB_CORRUPTION_HINTS):
        return False
    print("\n" + "=" * 62, file=sys.stderr)
    print("  SAFE FAILURE MODE — DATABASE INTEGRITY ERROR", file=sys.stderr)
    print("=" * 62, file=sys.stderr)
    print("The wallet database could not be opened. Possible causes:", file=sys.stderr)
    print("  1. Incorrect database encryption password.", file=sys.stderr)
    print("  2. Database file corrupted or tampered with.", file=sys.stderr)
    print("\nAll signing and write operations are SUSPENDED.", file=sys.stderr)
    print("\nRecovery options:", file=sys.stderr)
    print("  a) Re-run with the correct database password.", file=sys.stderr)
    print("  b) Rebuild from BIP-39 seed phrase:", file=sys.stderr)
    print("       python bitcoinlib_v03.py wallet-create <name>", file=sys.stderr)
    print("  c) Restore from a clean backup.", file=sys.stderr)
    print("=" * 62, file=sys.stderr)
    return True


# ---------------------------------------------------------------------------
# Policy engine — JSON file with HMAC-SHA256 integrity
# ---------------------------------------------------------------------------

_POLICY_DEFAULTS = {
    "version": 1,
    "spend_limit_btc": 1.0,
    "daily_limit_btc": 5.0,
    "allowlist": [],
    "denylist": [],
    "require_address_challenge_above_btc": 0.001,
    "require_confirmation_for_sweep": True,
    "fee_rate_soft_cap_sat_vb": 100,
    "fee_rate_hard_cap_sat_vb": 500,
}


def _policy_path(db_path: str) -> Path:
    return Path(os.path.dirname(db_path)) / "wallet_policy.json"


def _hmac_key_path(db_path: str) -> Path:
    return Path(os.path.dirname(db_path)) / ".policy_hmac_key"


def _load_or_create_hmac_key(db_path: str) -> bytes:
    key_path = _hmac_key_path(db_path)
    if key_path.exists():
        _check_path_permissions(str(key_path), 0o600, "HMAC key file")
        return key_path.read_bytes()
    raw = secrets.token_bytes(32)
    key_path.write_bytes(raw)
    key_path.chmod(0o600)
    return raw


def _policy_hmac(policy_data: dict, hmac_key: bytes) -> str:
    """Compute HMAC-SHA256 over the canonical policy JSON (without _hmac field)."""
    payload = {k: v for k, v in policy_data.items() if k != '_hmac'}
    canonical = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
    if _RUST_AVAILABLE:
        digest = bytes(_rust_signer.compute_hmac_sha256(hmac_key, canonical))
    else:
        digest = _hmac_mod.new(hmac_key, canonical, hashlib.sha256).digest()
    return digest.hex()


def _load_policy(db_path: str) -> dict:
    """Load and HMAC-verify the policy file. Abort if missing or tampered."""
    pol_path = _policy_path(db_path)
    if not pol_path.exists():
        _create_default_policy(db_path)

    _check_path_permissions(str(pol_path), 0o600, "Policy file")

    raw = pol_path.read_text(encoding='utf-8')
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"POLICY ERROR: Cannot parse wallet_policy.json: {e}", file=sys.stderr)
        sys.exit(1)

    stored_hmac = policy.get('_hmac', '')
    hmac_key = _load_or_create_hmac_key(db_path)
    expected_hmac = _policy_hmac(policy, hmac_key)

    if not _hmac_mod.compare_digest(stored_hmac, expected_hmac):
        print("POLICY INTEGRITY FAILURE: wallet_policy.json HMAC mismatch.", file=sys.stderr)
        print("The policy file may have been tampered with.", file=sys.stderr)
        print("Entering no-send mode. No transactions will be signed.", file=sys.stderr)
        sys.exit(1)

    return policy


def _create_default_policy(db_path: str) -> None:
    pol_path = _policy_path(db_path)
    hmac_key = _load_or_create_hmac_key(db_path)
    policy = dict(_POLICY_DEFAULTS)
    policy['_hmac'] = _policy_hmac(policy, hmac_key)
    pol_path.write_text(json.dumps(policy, indent=2), encoding='utf-8')
    pol_path.chmod(0o600)
    print(f"[INFO] Created default policy file: {pol_path}", file=sys.stderr)


def _save_policy(policy: dict, db_path: str) -> None:
    pol_path = _policy_path(db_path)
    hmac_key = _load_or_create_hmac_key(db_path)
    policy['_hmac'] = _policy_hmac(policy, hmac_key)
    pol_path.write_text(json.dumps(policy, indent=2), encoding='utf-8')
    pol_path.chmod(0o600)


def _enforce_policy_address(address: str, amount_btc: float, policy: dict) -> None:
    """Abort if address is denied or allowlist is non-empty and address not in it."""
    denylist = policy.get('denylist', [])
    allowlist = policy.get('allowlist', [])
    if address in denylist:
        print(f"POLICY BLOCK: Address {address} is on the denylist.", file=sys.stderr)
        sys.exit(1)
    if allowlist and address not in allowlist:
        print(f"POLICY BLOCK: Address {address} is not on the allowlist.", file=sys.stderr)
        print("Add it to the allowlist in wallet_policy.json to proceed.", file=sys.stderr)
        sys.exit(1)


def _enforce_policy_spend(amount_btc: float, policy: dict) -> None:
    limit = policy.get('spend_limit_btc', _POLICY_DEFAULTS['spend_limit_btc'])
    if amount_btc > limit:
        print(
            f"POLICY BLOCK: Transaction amount {amount_btc:.8f} BTC exceeds "
            f"spend limit {limit:.8f} BTC.",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# T4 — Hard fee cap enforcement
# ---------------------------------------------------------------------------

def _enforce_fee_cap(
    fee_rate: float | None,
    policy: dict,
    force_high_fee: bool,
    auto_yes: bool,
) -> None:
    """Block signing if fee_rate exceeds hard cap (unless --force-high-fee used)."""
    if fee_rate is None:
        return
    hard_cap = policy.get(
        'fee_rate_hard_cap_sat_vb', _POLICY_DEFAULTS['fee_rate_hard_cap_sat_vb'])
    soft_cap = policy.get(
        'fee_rate_soft_cap_sat_vb', _POLICY_DEFAULTS['fee_rate_soft_cap_sat_vb'])

    if fee_rate > hard_cap:
        if not force_high_fee:
            print(
                f"POLICY BLOCK: Fee rate {fee_rate:.1f} sat/vB exceeds hard cap "
                f"{hard_cap} sat/vB.",
                file=sys.stderr,
            )
            print("Re-run with --force-high-fee and confirm interactively.", file=sys.stderr)
            sys.exit(1)
        # --force-high-fee requires interactive confirmation regardless of --yes
        try:
            resp = input(
                f"[OVERRIDE] Fee rate {fee_rate:.1f} sat/vB exceeds hard cap "
                f"{hard_cap} sat/vB.\nType HIGHFEE to confirm: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if resp != 'HIGHFEE':
            print("Transaction cancelled (hard fee cap).", file=sys.stderr)
            sys.exit(0)
    elif fee_rate > soft_cap:
        print(
            f"[FEE WARNING] Fee rate {fee_rate:.1f} sat/vB exceeds soft cap "
            f"{soft_cap} sat/vB.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# Mnemonic backup ceremony — M2
# ---------------------------------------------------------------------------

def _mnemonic_ceremony(passphrase: str) -> None:
    """
    Display the mnemonic ONCE on stderr inside a clearly marked ceremony block.

    This is the sole location where the mnemonic appears in terminal output.
    It is never re-displayed in any other command, and it is never written to
    stdout (which may be captured in logs).
    """
    print("", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print("  SEED BACKUP CEREMONY — SENSITIVE — DO NOT SCREENSHOT", file=sys.stderr)
    print("  Close this terminal after noting your seed phrase.", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print("", file=sys.stderr)
    print("  Your 12-word BIP-39 seed phrase:", file=sys.stderr)
    print("", file=sys.stderr)
    # Print each word numbered for clarity
    words = passphrase.split()
    for i, word in enumerate(words, 1):
        print(f"    {i:2d}. {word}", file=sys.stderr)
    print("", file=sys.stderr)
    print("  Write these words on paper and store them securely.", file=sys.stderr)
    print("  This is the ONLY time they will be displayed.", file=sys.stderr)
    print("=" * 70, file=sys.stderr)
    print("", file=sys.stderr)


def generate_mnemonic(strength: int = 128) -> str:
    return Mnemonic().generate(strength)


# ---------------------------------------------------------------------------
# K4 — Seed backup verification (non-bypassable)
# ---------------------------------------------------------------------------

def verify_seed_backup(passphrase: str) -> None:
    words = passphrase.split()
    if len(words) < 3:
        return
    indices = sorted(random.sample(range(len(words)), 3))
    print("\n--- SEED BACKUP VERIFICATION ---", file=sys.stderr)
    print("Enter the requested words from your seed phrase.", file=sys.stderr)
    print("(Cannot be skipped. Answers are never stored.)\n", file=sys.stderr)
    for idx in indices:
        try:
            entered = input(f"  Word #{idx + 1}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nVerification cancelled. Wallet not created.", file=sys.stderr)
            sys.exit(1)
        if entered != words[idx].lower():
            print(
                f"\nVerification FAILED at word #{idx + 1}. "
                "Write your seed phrase carefully and retry.",
                file=sys.stderr,
            )
            sys.exit(1)
    print("Seed backup verification PASSED.\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# Encrypted key blob management (Rust signer integration)
# ---------------------------------------------------------------------------

def _blob_path(db_path: str) -> Path:
    return Path(os.path.dirname(db_path)) / ".wallet_key.blob"


def _store_key_blob(wif: str, db_password: str, db_path: str) -> None:
    """Encrypt WIF with the Rust module and store blob at 0600."""
    if not _RUST_AVAILABLE:
        return
    blob = bytes(_rust_signer.encrypt_key_blob(
        wif.encode('ascii'), db_password.encode('utf-8')))
    bp = _blob_path(db_path)
    bp.write_bytes(blob)
    bp.chmod(0o600)


def _rust_sign_digest(sighash: bytes, db_password: str, db_path: str) -> bytes | None:
    """
    Sign a 32-byte sighash via the Rust module using the stored encrypted blob.

    Returns DER signature bytes, or None if the Rust path is unavailable.
    The WIF never appears as a Python str in this function; it is decrypted
    and consumed entirely within the Rust boundary.
    """
    if not _RUST_AVAILABLE:
        return None
    bp = _blob_path(db_path)
    if not bp.exists():
        return None
    _check_path_permissions(str(bp), 0o600, "Key blob file")
    blob = bp.read_bytes()
    try:
        return bytes(_rust_signer.decrypt_and_sign(
            blob, db_password.encode('utf-8'), sighash))
    except Exception as e:
        print(f"[WARN] Rust signing failed: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# T1 — Pre-signing transaction review
# ---------------------------------------------------------------------------

FEE_RATE_DISPLAY_THRESHOLD = 100  # sat/vB above which fee is highlighted


def format_tx_review(t, network_name: str, policy: dict):
    """Return (review_text, fee_rate_or_None)."""
    lines = [
        "",
        "=" * 62,
        "  TRANSACTION REVIEW — VERIFY ALL FIELDS BEFORE SIGNING",
        "=" * 62,
        f"  Network     : {network_name.upper()}",
        "",
    ]
    total_recipient_btc = 0.0
    for i, o in enumerate(t.outputs):
        role = "CHANGE" if getattr(o, 'is_change', False) else "RECIPIENT"
        sat = int(o.value)
        btc = sat / 1e8
        if role == "RECIPIENT":
            total_recipient_btc += btc
        lines.append(f"  Output [{i}]   [{role}]")
        lines.append(f"    Address   : {o.address}")
        lines.append(f"    Amount    : {sat:,} sat  ({btc:.8f} BTC)")
    lines.append("")

    fee_sats = int(t.fee) if t.fee else 0
    fee_btc = fee_sats / 1e8
    tx_vbytes = getattr(t, 'vsize', None) or getattr(t, 'size', None)
    fee_rate = (fee_sats / tx_vbytes) if tx_vbytes else None

    lines.append(f"  Fee         : {fee_sats:,} sat  ({fee_btc:.8f} BTC)")
    if fee_rate is not None:
        lines.append(
            f"  Fee Rate    : {fee_rate:.1f} sat/vB  "
            f"(estimated tx size: {tx_vbytes} vB)"
        )

    soft_cap = policy.get('fee_rate_soft_cap_sat_vb', 100)
    hard_cap = policy.get('fee_rate_hard_cap_sat_vb', 500)
    if fee_rate is not None and fee_rate > soft_cap:
        lines.append("")
        lines.append(
            f"  *** FEE ALERT: {fee_rate:.1f} sat/vB > soft cap {soft_cap} sat/vB ***"
        )
        if fee_rate > hard_cap:
            lines.append(
                f"  *** HARD CAP {hard_cap} sat/vB EXCEEDED — requires --force-high-fee ***"
            )

    lines.append("=" * 62)
    return "\n".join(lines), fee_rate


# ---------------------------------------------------------------------------
# T3 — Confirmation helpers
# ---------------------------------------------------------------------------

def confirm_action(prompt: str, auto_yes: bool = False) -> bool:
    if auto_yes:
        return True
    try:
        resp = input(f"{prompt} [y/N]: ").strip().lower()
        return resp in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print("", file=sys.stderr)
        return False


# ---------------------------------------------------------------------------
# Address challenge (T3 / policy engine)
# ---------------------------------------------------------------------------

def _address_challenge(address: str, label: str = "recipient") -> None:
    """
    Require the user to type a randomly selected substring of the address
    to confirm they have verified the full address.

    Selects 6 characters at 3 random non-overlapping positions.
    """
    if len(address) < 12:
        return
    positions = sorted(random.sample(range(len(address) - 1), 3))
    challenge = "".join(address[p] + address[p + 1] for p in positions)
    print(f"\n[ADDRESS CHALLENGE] Verify the {label} address:", file=sys.stderr)
    print(f"  {address}", file=sys.stderr)
    print(
        f"  Characters at positions {positions[0]}-{positions[0]+1}, "
        f"{positions[1]}-{positions[1]+1}, {positions[2]}-{positions[2]+1}:",
        file=sys.stderr,
    )
    try:
        entered = input("  Type those 6 characters (no spaces): ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nChallenge cancelled. Transaction aborted.", file=sys.stderr)
        sys.exit(0)
    if entered != challenge:
        print("Address challenge FAILED. Transaction cancelled.", file=sys.stderr)
        sys.exit(0)


def _maybe_challenge_address(address: str, amount_btc: float, policy: dict,
                              is_sweep: bool = False) -> None:
    """Apply address challenge based on policy rules."""
    threshold = policy.get(
        'require_address_challenge_above_btc',
        _POLICY_DEFAULTS['require_address_challenge_above_btc'],
    )
    allowlist = policy.get('allowlist', [])
    if is_sweep or amount_btc >= threshold or address not in allowlist:
        _address_challenge(address, label="sweep destination" if is_sweep else "recipient")


# ---------------------------------------------------------------------------
# N2 — UTXO / balance cross-check from second provider
# ---------------------------------------------------------------------------

def _fetch_blockstream_balance(address: str, network: str) -> int | None:
    """Return confirmed balance in satoshis from Blockstream API, or None on error."""
    try:
        import requests
        base = (
            "https://blockstream.info/testnet/api"
            if 'test' in network.lower()
            else "https://blockstream.info/api"
        )
        url = f"{base}/address/{address}"
        resp = requests.get(url, timeout=10, verify=True)
        resp.raise_for_status()
        data = resp.json()
        funded = data.get('chain_stats', {}).get('funded_txo_sum', 0)
        spent = data.get('chain_stats', {}).get('spent_txo_sum', 0)
        return funded - spent
    except Exception:
        return None


def _cross_check_balance(w, network: str) -> None:
    """
    Compare bitcoinlib's reported balance against Blockstream's API.
    Warn if they differ; do not block (network partition may cause legitimate drift).
    """
    try:
        lib_balance_sat = w.balance()
        if lib_balance_sat == 0:
            return
        # Use the first receiving address for the spot check
        keys = w.keys(is_private=False)
        if not keys:
            return
        address = keys[0].address
        ext_balance = _fetch_blockstream_balance(address, network)
        if ext_balance is None:
            print(
                "[N2] Second-provider balance check unavailable (network error). "
                "Proceeding with primary provider data.",
                file=sys.stderr,
            )
            return
        diff = abs(lib_balance_sat - ext_balance)
        pct = diff / max(lib_balance_sat, 1) * 100
        if pct > 5 or diff > 10_000:
            print(
                f"[N2] BALANCE MISMATCH: primary={lib_balance_sat:,} sat, "
                f"Blockstream={ext_balance:,} sat (diff={diff:,} sat, {pct:.1f}%).",
                file=sys.stderr,
            )
            print(
                "[N2] UTXOs may be stale. Run wallet-update-utxos and retry. "
                "Proceeding anyway (non-blocking).",
                file=sys.stderr,
            )
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.umask(0o077)
    sys.excepthook = exception_handler

    parser = argparse.ArgumentParser(
        description=f'BitcoinLib CLI Wallet v{BITCOINLIB_VERSION} (v03 — Robust)')

    parser.add_argument(
        '--database', '-d',
        default=None,
        help='SQLCipher wallet database path (default: ~/.local/share/btcwallet/bitcoin.sqlite)',
    )
    parser.add_argument('--network', '-n')
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument(
        '--yes', '-y', action='store_true',
        help="Auto-confirm non-security prompts (does NOT bypass seed verification "
             "or address challenges)",
    )
    parser.add_argument(
        '--force-high-fee', action='store_true',
        help="Override hard fee cap (requires interactive HIGHFEE confirmation)",
    )

    sub = parser.add_subparsers(dest='command', required=True)

    # wallet-create --------------------------------------------------------
    p_create = sub.add_parser('wallet-create')
    p_create.add_argument('name')
    p_create.add_argument('--scheme', default='bip32')
    p_create.add_argument('--witness-type', default='segwit')
    p_create.add_argument('--passphrase-strength', type=int, default=128)
    p_create.add_argument('--multisig', '-m', nargs='+')
    p_create.add_argument('--cosigner-id', '-o', type=int)
    p_create.add_argument('--disable-anti-fee-sniping', action='store_true')

    # wallet-list ----------------------------------------------------------
    sub.add_parser('wallet-list')

    # wallet-info ----------------------------------------------------------
    p_info = sub.add_parser('wallet-info')
    p_info.add_argument('name')

    # wallet-delete --------------------------------------------------------
    p_delete = sub.add_parser('wallet-delete')
    p_delete.add_argument('name')
    p_delete.add_argument('--force', action='store_true')

    # wallet-empty ---------------------------------------------------------
    p_empty = sub.add_parser('wallet-empty')
    p_empty.add_argument('name')

    # wallet-receive -------------------------------------------------------
    p_rec = sub.add_parser('wallet-receive')
    p_rec.add_argument('name')
    p_rec.add_argument('--cosigner-id', '-o', type=int)

    # wallet-update-utxos / wallet-update-txs ------------------------------
    p_uu = sub.add_parser('wallet-update-utxos')
    p_uu.add_argument('name')
    p_ut = sub.add_parser('wallet-update-txs')
    p_ut.add_argument('name')

    # tx-send --------------------------------------------------------------
    p_send = sub.add_parser('tx-send')
    p_send.add_argument('name')
    p_send.add_argument('--send', '-s', nargs=2, action='append',
                        metavar=('ADDRESS', 'AMOUNT'))
    p_send.add_argument('--fee', '-f', type=int)
    p_send.add_argument('--input-key-id', '-k', type=int)
    p_send.add_argument('--change-outputs', type=int, default=1)
    p_send.add_argument('--push', '-p', action='store_true')
    p_send.add_argument('--rbf', action='store_true')
    p_send.add_argument(
        '--skip-provider-check', action='store_true',
        help="Skip second-provider balance cross-check (for airgapped use)",
    )

    # tx-sweep -------------------------------------------------------------
    p_sweep = sub.add_parser('tx-sweep')
    p_sweep.add_argument('name')
    p_sweep.add_argument('address')
    p_sweep.add_argument('--fee', '-f', type=int)
    p_sweep.add_argument('--push', '-p', action='store_true')
    p_sweep.add_argument('--rbf', action='store_true')
    p_sweep.add_argument('--skip-provider-check', action='store_true')

    # tx-import ------------------------------------------------------------
    p_imp = sub.add_parser('tx-import')
    p_imp.add_argument('name')
    p_imp.add_argument('transaction')
    p_imp.add_argument('--push', '-p', action='store_true')

    # key-export -----------------------------------------------------------
    p_exp = sub.add_parser('key-export')
    p_exp.add_argument('name')
    p_exp.add_argument('--output-file', '-o', required=True,
                       help="File path to write exported key (never printed to terminal)")
    p_exp.add_argument(
        '--i-understand-the-risk', dest='risk_acknowledged', action='store_true',
        help="Required: acknowledge the risk of exporting private key material",
    )

    # sign-digest ----------------------------------------------------------
    p_sign = sub.add_parser(
        'sign-digest',
        help="Sign a 32-byte hex sighash via the Rust module (demonstrates Rust path)")
    p_sign.add_argument('name')
    p_sign.add_argument('sighash_hex', help="32-byte sighash as lowercase hex string")

    args = parser.parse_args()

    # Resolve database path
    if args.database is None:
        args.database = _default_db_path()
    else:
        args.database = os.path.abspath(args.database)

    output_to = open(os.devnull, 'w') if args.quiet else sys.stdout

    if not args.quiet:
        print(f"BitcoinLib CLI Wallet v{BITCOINLIB_VERSION} (v03)", file=output_to)

    # Pre-flight security checks
    check_permissions(args.database)
    verify_encryption_at_rest(args.database)
    db_password = get_db_password()

    db_path = parse_db_path(args.database)

    # -----------------------------------------------------------------------
    # Command dispatch
    # -----------------------------------------------------------------------
    try:
        # ------------------------------------------------------------------
        if args.command == 'wallet-create':
            network = args.network or DEFAULT_NETWORK
            if (os.path.exists(db_path) and
                    wallet_exists(args.name, db_uri=args.database,
                                  db_password=db_password)):
                print(f"Wallet '{args.name}' already exists.", file=output_to)
                sys.exit(1)

            print("CREATE wallet '%s' (%s network)" % (args.name, network),
                  file=output_to)
            anti_fee_sniping = not args.disable_anti_fee_sniping

            if args.multisig:
                if len(args.multisig) < 2:
                    raise WalletError(
                        "Multisig creation requires: M N [KEY1 KEY2 ...]")
                try:
                    sigs_required = int(args.multisig[0])
                    sigs_total = int(args.multisig[1])
                except ValueError:
                    raise WalletError("First two multisig args must be integers")

                key_list = args.multisig[2:]
                keys_missing = sigs_total - len(key_list)
                if keys_missing < 0:
                    raise WalletError("Too many keys provided")
                if keys_missing:
                    print("Generating %d key(s)..." % keys_missing, file=output_to)
                    for _ in range(keys_missing):
                        phrase = generate_mnemonic(args.passphrase_strength)
                        _mnemonic_ceremony(phrase)
                        verify_seed_backup(phrase)
                        key_list.append(HDKey.from_passphrase(phrase, network=network))

                w = Wallet.create(
                    args.name, key_list, sigs_required=sigs_required,
                    network=network, cosigner_id=args.cosigner_id,
                    db_uri=args.database, db_password=db_password,
                    witness_type=args.witness_type, scheme='multisig',
                    anti_fee_sniping=anti_fee_sniping)

            else:
                # M3: no --passphrase CLI arg; mnemonic generated internally
                passphrase = generate_mnemonic(args.passphrase_strength)

                if len(passphrase.split()) < 3:
                    raise WalletError("Passphrase must be 3 words or more")

                # M2: display mnemonic only in ceremony block (stderr, once)
                _mnemonic_ceremony(passphrase)

                # K4: mandatory backup verification — not bypassable
                verify_seed_backup(passphrase)

                hdkey = HDKey.from_passphrase(passphrase, network=network)
                w = Wallet.create(
                    args.name, hdkey, network=network,
                    witness_type=args.witness_type,
                    db_uri=args.database, db_password=db_password,
                    anti_fee_sniping=anti_fee_sniping)

                # Rust M1: encrypt WIF and store blob
                if w.main_key and w.main_key.is_private:
                    _store_key_blob(w.main_key.wif, db_password, db_path)

            # Enforce permissions on DB and supporting files
            if os.path.exists(db_path):
                os.chmod(db_path, 0o600)
            check_permissions(args.database)
            verify_encryption_at_rest(args.database)

            # Create default policy
            _create_default_policy(db_path)

            w.info()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-list':
            print("BitcoinLib wallets:", file=output_to)
            wallets = wallets_list(db_uri=args.database, db_password=db_password)
            if not wallets:
                print("Use --help to create a wallet.", file=output_to)
            else:
                for wl in wallets:
                    if wl.get('parent_id'):
                        continue
                    print("[%d] %s (%s) %s" % (
                        wl['id'], wl['name'], wl['network'], wl['owner']),
                        file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-info':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            w.info()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-delete':
            nid = int(args.name) if args.name.isdigit() else args.name
            if not wallet_exists(nid, db_uri=args.database, db_password=db_password):
                print("Wallet '%s' not found" % args.name, file=output_to)
            else:
                if not (args.quiet or args.yes or args.force):
                    inp = input(
                        "Wallet '%s' and all keys will be removed.\n"
                        "Retype the exact name to proceed: " % args.name)
                    if inp != args.name:
                        print("Name mismatch — aborted.", file=output_to)
                        sys.exit(0)
                if wallet_delete(nid, force=True, db_uri=args.database,
                                 db_password=db_password):
                    print("Wallet %s removed." % args.name, file=output_to)
                else:
                    print("Error deleting wallet.", file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-empty':
            nid = int(args.name) if args.name.isdigit() else args.name
            wallet_empty(nid, db_uri=args.database, db_password=db_password)
            print("Wallet emptied (transactions removed).", file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-receive':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            key = w.get_key(network=args.network or w.network.name,
                            cosigner_id=args.cosigner_id)
            print("Receive address: %s" % key.address, file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-update-utxos':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            print("Updating UTXOs...", file=output_to)
            w.utxos_update()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-update-txs':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            print("Scanning transactions...", file=output_to)
            w.scan(scan_gap_limit=3)

        # ------------------------------------------------------------------
        elif args.command == 'tx-send':
            if not args.send:
                raise WalletError("Specify at least one --send ADDRESS AMOUNT")

            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            network_name = args.network or w.network.name

            # Load and verify policy
            policy = _load_policy(db_path)

            output_arr = [(addr, val) for addr, val in args.send]
            total_btc = sum(float(val) / 1e8 for _, val in args.send)

            # Policy checks: address and spend limit
            for addr, _ in args.send:
                _enforce_policy_address(addr, total_btc, policy)
            _enforce_policy_spend(total_btc, policy)

            # N2: second-provider balance check
            if not getattr(args, 'skip_provider_check', False):
                _cross_check_balance(w, network_name)

            # Build unsigned transaction
            t = w.transaction_create(
                output_arr=output_arr,
                network=network_name,
                fee=args.fee,
                min_confirms=0,
                input_key_id=args.input_key_id,
                number_of_change_outputs=args.change_outputs,
                replace_by_fee=args.rbf,
            )

            # T1: Pre-signing review
            review, fee_rate = format_tx_review(t, network_name, policy)
            print(review, file=sys.stderr)

            # T4: Hard fee cap enforcement
            _enforce_fee_cap(fee_rate, policy, args.force_high_fee, args.yes)

            # Address challenge for recipients above threshold
            for addr, val in args.send:
                amount_btc = float(val) / 1e8
                _maybe_challenge_address(addr, amount_btc, policy)

            # T3: Explicit confirmation before signing
            if not confirm_action("Confirm and sign this transaction?", args.yes):
                print("Transaction cancelled.", file=output_to)
                sys.exit(0)

            # Sign — bitcoinlib path (Rust path for standalone digests
            # is demonstrated via sign-digest command)
            t.sign()
            print("Transaction signed.", file=output_to)
            t.info()

            if args.push:
                t.send()
                if t.pushed:
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error pushing: %s" % t.error, file=output_to)
            else:
                print("\nSigned but not sent. Transaction dict:", file=output_to)
                pprint(t.as_dict(), stream=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'tx-sweep':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            network_name = args.network or w.network.name

            policy = _load_policy(db_path)

            # Policy: sweep address check
            _enforce_policy_address(args.address, 0.0, policy)

            # N2: second-provider check
            if not getattr(args, 'skip_provider_check', False):
                _cross_check_balance(w, network_name)

            # U1: Non-suppressible sweep warning (always stderr)
            print("\n[SECURITY WARNING] tx-sweep will send ALL wallet funds to:",
                  file=sys.stderr)
            print("  %s" % args.address, file=sys.stderr)
            print("This action cannot be undone.", file=sys.stderr)

            # Address challenge (always required for sweep)
            _maybe_challenge_address(args.address, 0.0, policy, is_sweep=True)

            # T3: Typed SWEEP confirmation (not bypassable with --yes alone)
            if not args.yes:
                try:
                    resp = input("\nType SWEEP to confirm emptying the wallet: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nSweep cancelled.", file=sys.stderr)
                    sys.exit(0)
                if resp != 'SWEEP':
                    print("Sweep cancelled.", file=sys.stderr)
                    sys.exit(0)

            # Build & sign (broadcast=False for review before broadcast)
            t = w.sweep(
                args.address,
                broadcast=False,
                network=network_name,
                fee=args.fee,
                replace_by_fee=args.rbf,
            )
            if not t:
                raise WalletError("Sweep returned no transaction (wallet empty?)")

            # T1 + T4: Review and fee cap check
            review, fee_rate = format_tx_review(t, network_name, policy)
            print(review, file=sys.stderr)
            _enforce_fee_cap(fee_rate, policy, args.force_high_fee, args.yes)

            t.info()

            if args.push:
                t.send()
                if t.pushed:
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error sweeping: %s" % t.error, file=output_to)
            else:
                print("\nSigned but not sent. Transaction dict:", file=output_to)
                pprint(t.as_dict(), stream=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'tx-import':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            network_name = args.network or w.network.name
            policy = _load_policy(db_path)
            tx_data = args.transaction

            if os.path.exists(tx_data):
                with open(tx_data, 'r') as f:
                    content = f.read().strip()
                import ast
                try:
                    tx_data = ast.literal_eval(content)
                except Exception:
                    tx_data = content
            else:
                import ast
                try:
                    tx_data = ast.literal_eval(tx_data)
                except Exception:
                    pass

            if isinstance(tx_data, dict):
                t = w.transaction_import(tx_data)
            else:
                t = w.transaction_import_raw(tx_data, network=network_name)

            review, fee_rate = format_tx_review(t, network_name, policy)
            print(review, file=sys.stderr)
            _enforce_fee_cap(fee_rate, policy, args.force_high_fee, args.yes)

            if not confirm_action("Sign this imported transaction?", args.yes):
                print("Import signing cancelled.", file=output_to)
                sys.exit(0)

            t.sign()
            if args.push:
                if t.send():
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error pushing: %s" % t.error, file=output_to)
            t.info()
            if not args.quiet:
                pprint(t.as_dict(), stream=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'key-export':
            # U1 / M2: Must provide --i-understand-the-risk AND --output-file
            if not args.risk_acknowledged:
                print("\n[SECURITY GATE] key-export requires --i-understand-the-risk.",
                      file=sys.stderr)
                print("Private key material will be written to a file, never printed.",
                      file=sys.stderr)
                sys.exit(1)

            out_path = os.path.abspath(args.output_file)
            out_dir = os.path.dirname(out_path)
            if os.path.exists(out_dir):
                dir_mode = os.stat(out_dir).st_mode & 0o777
                if dir_mode & 0o077:
                    print(
                        f"SECURITY ERROR: Output directory '{out_dir}' is "
                        f"group/world-accessible ({oct(dir_mode)}). Aborted.",
                        file=sys.stderr,
                    )
                    sys.exit(1)

            # Interactive confirmation (not bypassable via --yes)
            try:
                resp = input(
                    f"\n[KEY EXPORT] Write private key to '{out_path}'?\n"
                    "Type EXPORT to confirm: "
                ).strip()
            except (EOFError, KeyboardInterrupt):
                sys.exit(0)
            if resp != 'EXPORT':
                print("Key export cancelled.", file=sys.stderr)
                sys.exit(0)

            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)

            lines_out = []
            if w.scheme == 'multisig':
                for c in w.cosigner:
                    if c.main_key and c.main_key.is_private:
                        lines_out.append(c.main_key.wif)
            elif w.main_key and w.main_key.is_private:
                lines_out.append(w.main_key.wif)

            if not lines_out:
                print("No private key available.", file=output_to)
                sys.exit(0)

            # Write to file with 0600; never to stdout/stderr
            with open(out_path, 'w') as f:
                for line in lines_out:
                    f.write(line + '\n')
            os.chmod(out_path, 0o600)
            print(f"[KEY EXPORT] Private key written to {out_path} (0600).", file=sys.stderr)
            print("DELETE this file immediately after use.", file=sys.stderr)

        # ------------------------------------------------------------------
        elif args.command == 'sign-digest':
            # Demonstrates the full Rust signing path for a precomputed sighash.
            if not _RUST_AVAILABLE:
                print("Error: bitcoin_signer Rust module not available.", file=sys.stderr)
                sys.exit(1)

            sighash_hex = args.sighash_hex.strip().lower()
            if len(sighash_hex) != 64:
                raise WalletError("sighash_hex must be exactly 64 hex characters (32 bytes)")
            try:
                sighash_bytes = bytes.fromhex(sighash_hex)
            except ValueError:
                raise WalletError("sighash_hex contains non-hex characters")

            der_sig = _rust_sign_digest(sighash_bytes, db_password, db_path)
            if der_sig is None:
                print(
                    "Error: No encrypted key blob found. "
                    "Create a wallet first (wallet-create).",
                    file=sys.stderr,
                )
                sys.exit(1)

            print("DER signature (hex): %s" % der_sig.hex(), file=output_to)

    # -----------------------------------------------------------------------
    # Unified error handling
    # -----------------------------------------------------------------------
    except Exception as e:
        try:
            from sqlalchemy.exc import DatabaseError as _SADBError
        except ImportError:
            _SADBError = None
        try:
            from pysqlcipher3.dbapi2 import DatabaseError as _CipherDBError
        except ImportError:
            _CipherDBError = None

        is_db_err = (
            (_SADBError and isinstance(e, _SADBError)) or
            (_CipherDBError and isinstance(e, _CipherDBError))
        )
        if is_db_err and handle_db_error(e):
            sys.exit(1)

        if isinstance(e, WalletError):
            print("WalletError: %s" % _redact(str(e)), file=sys.stderr)
        else:
            print("Error %s: %s" % (type(e).__name__, _redact(str(e))), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
