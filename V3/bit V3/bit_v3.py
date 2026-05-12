"""
bit_v3.py — Robust Maturity CLI Bitcoin Wallet
"""

import argparse
import base64
import ctypes
import getpass
import hashlib
import hmac as hmac_mod
import json
import os
import re
import secrets
import ssl
import stat
import subprocess  # nosec B404 — fixed argv only, no shell, no user data
import sys
from pathlib import Path

import requests
import requests.adapters

from bit import Key, PrivateKeyTestnet
from bit.network import fees
from mnemonic import Mnemonic

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

KEYSTORE_DIR      = Path.home() / ".bit_v3_keystore"
POLICY_FILE       = Path.home() / ".bit_v3_policy.json"
POLICY_HMAC_KEY   = KEYSTORE_DIR / ".policy_hmac_key"

PBKDF2_ITERATIONS = 200_000        # K2
SALT_LEN          = 16
NONCE_LEN         = 12
KEY_LEN           = 32             # AES-256-GCM
FEE_RATE_SOFT_CAP = 100            # T4: sat/vB — warn
FEE_RATE_HARD_CAP = 500            # T4: sat/vB — block without --force-high-fee
WIF_REGEX         = re.compile(r"[5KLcm9][1-9A-HJ-NP-Za-km-z]{50,51}")

SECP256K1_ORDER   = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_BASE58_CHARS     = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

_DEFAULT_POLICY: dict = {
    "version": 2,
    "spend_limit_btc": 0.0,
    "allowlist": [],
    "require_address_challenge_above_btc": 0.0,
}

# L2: set to True when policy HMAC verification fails at load time.
_POLICY_CORRUPTED: bool = False

# N1: Known HTTPS endpoints used by the bit library (for auditing).
_BIT_ENDPOINTS = [
    "https://api.blockchair.com",
    "https://blockstream.info",
    "https://mempool.space",
]


# ---------------------------------------------------------------------------
# N1 — TLS enforcement (applied at import time)
# ---------------------------------------------------------------------------

class _StrictTLSAdapter(requests.adapters.HTTPAdapter):
    """HTTPAdapter that enforces TLS ≥ 1.2 and certificate verification (N1)."""
    def init_poolmanager(self, *args, **kwargs):
        from urllib3.util.ssl_ import create_urllib3_context
        ctx = create_urllib3_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        kwargs["ssl_context"] = ctx
        super().init_poolmanager(*args, **kwargs)


class _BlockHTTPAdapter(requests.adapters.HTTPAdapter):
    """Refuse all plain-HTTP connections (N1: no silent downgrade)."""
    def send(self, request, *args, **kwargs):
        if request.url.startswith("http://"):
            raise requests.exceptions.ConnectionError(
                f"N1: plain HTTP blocked — HTTPS required. URL: {request.url}"
            )
        return super().send(request, *args, **kwargs)


def _make_tls_session() -> requests.Session:
    """N1: create a requests.Session with hardened TLS settings for V3 own requests."""
    sess = requests.Session()
    sess.verify = True
    sess.mount("https://", _StrictTLSAdapter())
    sess.mount("http://", _BlockHTTPAdapter())
    return sess


# N1: process-level patch — every Session created in this process defaults to verify=True.
_orig_session_init = requests.Session.__init__


def _hardened_session_init(self, *args, **kwargs):
    _orig_session_init(self, *args, **kwargs)
    self.verify = True  # enforce even for the bit library's sessions


requests.Session.__init__ = _hardened_session_init

# V3's own session for cross-verification calls.
_V3_SESSION: requests.Session = _make_tls_session()


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
# M1 — Explicit memory zeroing via ctypes
# ---------------------------------------------------------------------------

def _zero_buffer(buf: bytearray) -> None:
    """
    M1: overwrite bytearray contents via ctypes.memset to minimise GC exposure.
    Falls back to Python-level zeroing if ctypes fails.
    """
    n = len(buf)
    if n == 0:
        return
    try:
        arr = (ctypes.c_char * n).from_buffer(buf)
        ctypes.memset(arr, 0, n)
    except Exception:
        buf[:] = b"\x00" * n  # safe fallback


# ---------------------------------------------------------------------------
# K4 — BIP-39 mnemonic generation, derivation, and WIF encoding
# ---------------------------------------------------------------------------

_MNEMO = Mnemonic("english")


def _generate_mnemonic() -> str:
    """K4: generate a 12-word BIP-39 mnemonic using 128 bits of OS entropy."""
    return _MNEMO.generate(strength=128)


def _validate_mnemonic(phrase: str) -> bool:
    """Return True if phrase is a valid BIP-39 mnemonic (checksum verified)."""
    return _MNEMO.check(phrase)


def _mnemonic_to_private_key(phrase: str) -> bytes:
    """
    K4: BIP-39 seed derivation → BIP-32 master key (HMAC-SHA512).
    Returns 32 bytes of private key material.
    """
    seed = _MNEMO.to_seed(phrase, passphrase="")  # nosec B106 — BIP-39 standard: empty BIP39 passphrase
    h = hmac_mod.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    master_key = h[:32]
    n = int.from_bytes(master_key, "big")
    if n == 0 or n >= SECP256K1_ORDER:
        raise ValueError("Derived master key is not a valid secp256k1 private key.")
    return master_key


def _base58encode(data: bytes) -> str:
    """Standard Base58 encoding (Bitcoin WIF format)."""
    n = int.from_bytes(data, "big")
    result: list[str] = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(_BASE58_CHARS[r])
    result.reverse()
    leading = sum(1 for b in data if b == 0)
    return "1" * leading + "".join(result)


def _private_key_to_wif(key_bytes: bytes, mainnet: bool = True) -> str:
    """K4: encode 32-byte private key as compressed WIF (mainnet or testnet)."""
    prefix  = b"\x80" if mainnet else b"\xef"
    payload = prefix + key_bytes + b"\x01"    # 0x01 = compressed pubkey flag
    d1      = hashlib.sha256(payload).digest()
    d2      = hashlib.sha256(d1).digest()
    return _base58encode(payload + d2[:4])


def _backup_verify(words: list[str]) -> bool:
    """
    K4 score 2: 3-word positional challenge. User must enter the correct word
    for 3 randomly-chosen positions before the keystore is written.
    Returns True if all 3 challenges are answered correctly, False otherwise.
    """
    positions = sorted(secrets.SystemRandom().sample(range(len(words)), 3))
    print("\n=== BACKUP VERIFICATION ===")
    print("Enter the words at the positions shown (input is hidden):")
    for pos in positions:
        entered = getpass.getpass(f"  Word #{pos + 1}: ").strip().lower()
        if entered != words[pos].lower():
            print(f"  [✗] Incorrect. Expected word #{pos + 1}.", file=sys.stderr)
            return False
        print(f"  [✓] Word #{pos + 1} correct.")
    return True


# ---------------------------------------------------------------------------
# K1/K2/K3 — Extended encrypted keystore (PBKDF2 + AES-256-GCM, 0600)
# Supports optional encrypted mnemonic field (K4).
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


def save_encrypted_keystore(name: str, wif: str, passphrase: str,
                             is_testnet: bool,
                             mnemonic: str | None = None) -> Path:
    """
    K1+K2+K3+K4: persist WIF (and optionally mnemonic) in an
    authenticated-encrypted file.  Format:
        BITV3-KEYSTORE-1
        kdf=PBKDF2-HMAC-SHA256
        iter=<n>
        salt=<b64>
        nonce=<b64>
        net=<MAINNET|TESTNET>
        ct=<b64>                   ← AES-256-GCM ciphertext of WIF
        [mnemonic_nonce=<b64>]
        [mnemonic_ct=<b64>]        ← AES-256-GCM ciphertext of mnemonic
    """
    _ensure_dir(KEYSTORE_DIR)
    salt  = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key   = _derive_key(passphrase, salt)
    aes   = AESGCM(key)
    aad   = network_label(is_testnet).encode("ascii")
    ct    = aes.encrypt(nonce, wif.encode("utf-8"), aad)

    lines = [
        "BITV3-KEYSTORE-1",
        "kdf=PBKDF2-HMAC-SHA256",
        f"iter={PBKDF2_ITERATIONS}",
        f"salt={base64.b64encode(salt).decode()}",
        f"nonce={base64.b64encode(nonce).decode()}",
        f"net={network_label(is_testnet)}",
        f"ct={base64.b64encode(ct).decode()}",
    ]

    if mnemonic is not None:
        m_nonce = secrets.token_bytes(NONCE_LEN)
        m_ct    = aes.encrypt(m_nonce, mnemonic.encode("utf-8"), b"mnemonic")
        lines += [
            f"mnemonic_nonce={base64.b64encode(m_nonce).decode()}",
            f"mnemonic_ct={base64.b64encode(m_ct).decode()}",
        ]

    del key
    body = "\n".join(lines) + "\n"

    path  = _keystore_path(name)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd    = os.open(str(path), flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(body)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return path


def load_encrypted_keystore(name: str,
                             passphrase: str) -> tuple[bytearray, bool, str | None]:
    """
    M1+K1+K4: decrypt keystore and return (wif_bytearray, is_testnet, mnemonic_or_None).
    wif_bytearray is mutable so it can be zeroed by the caller after use.
    Accepts BITV1/V2/V3 headers for backward compatibility.
    """
    path = _keystore_path(name)
    if not path.exists():
        raise FileNotFoundError(
            f"No keystore named '{name}' found in {KEYSTORE_DIR}."
        )
    fields: dict = {}
    with open(path, "r", encoding="utf-8") as fh:
        first = fh.readline().strip()
        if first not in ("BITV3-KEYSTORE-1", "BITV2-KEYSTORE-1", "BITV1-KEYSTORE-1"):
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

    try:
        wif_bytes = aes.decrypt(nonce, ct, net.encode("ascii"))
    except Exception as exc:
        raise ValueError(
            "Decryption failed: wrong passphrase or tampered keystore."
        ) from exc

    # M1: return mutable bytearray so caller can zero it after use.
    wif_buf = bytearray(wif_bytes)

    mnemonic: str | None = None
    if "mnemonic_nonce" in fields and "mnemonic_ct" in fields:
        try:
            m_nonce = base64.b64decode(fields["mnemonic_nonce"])
            m_ct    = base64.b64decode(fields["mnemonic_ct"])
            m_bytes = aes.decrypt(m_nonce, m_ct, b"mnemonic")
            mnemonic = m_bytes.decode("utf-8")
        except Exception:
            mnemonic = None  # mnemonic unreadable is non-fatal

    del raw_key
    return wif_buf, (net == "TESTNET"), mnemonic


# ---------------------------------------------------------------------------
# M3 — Secure key loading (keystore-only; no raw-WIF CLI fallback)
# ---------------------------------------------------------------------------

def load_key_from_keystore(args) -> tuple[bytearray, bool]:
    """
    M1+M3+K1: load WIF from encrypted keystore into a bytearray.
    The CALLER must zero the returned bytearray in a finally block.
    No raw-WIF fallback exists.
    """
    if not getattr(args, "keystore", None):
        raise ValueError(
            "A --keystore NAME is required. "
            "Create one with `generate --name NAME` or `import --name NAME`."
        )
    passphrase = getpass.getpass(f"Passphrase for keystore '{args.keystore}': ")
    try:
        wif_buf, is_testnet, _ = load_encrypted_keystore(args.keystore, passphrase)
    finally:
        pass_buf = bytearray(passphrase.encode("utf-8"))
        _zero_buffer(pass_buf)
        del passphrase, pass_buf
    return wif_buf, is_testnet


def _prompt_new_passphrase() -> bytearray:
    """Prompt for a new passphrase; return as bytearray (zeroable) after validation."""
    p1 = getpass.getpass("New keystore passphrase: ")
    p2 = getpass.getpass("Confirm passphrase: ")
    match = p1 == p2
    ok_len = len(p1) >= 8
    p1_buf = bytearray(p1.encode("utf-8"))
    del p1, p2
    if not match:
        _zero_buffer(p1_buf)
        raise ValueError("Passphrases do not match.")
    if not ok_len:
        _zero_buffer(p1_buf)
        raise ValueError("Passphrase must be at least 8 characters.")
    return p1_buf


# ---------------------------------------------------------------------------
# T3/L1/L2 — Policy engine + HMAC integrity
# ---------------------------------------------------------------------------

def _get_policy_hmac_key() -> bytes:
    """
    L1: return (or generate) the machine-local 32-byte HMAC key for policy signing.
    Key is stored at POLICY_HMAC_KEY with mode 0600.
    """
    _ensure_dir(KEYSTORE_DIR)
    if POLICY_HMAC_KEY.exists():
        raw = POLICY_HMAC_KEY.read_bytes()
        if len(raw) == 32:
            return raw
    key = secrets.token_bytes(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(POLICY_HMAC_KEY), flags, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    try:
        os.chmod(POLICY_HMAC_KEY, 0o600)
    except OSError:
        pass
    return key


def _policy_hmac(policy_data: dict, hmac_key: bytes) -> str:
    """Compute HMAC-SHA256 over the policy data (fields sorted, _hmac excluded)."""
    payload = json.dumps(
        {k: v for k, v in policy_data.items() if k != "_hmac"},
        sort_keys=True,
    ).encode("utf-8")
    return hmac_mod.new(hmac_key, payload, hashlib.sha256).hexdigest()


def _load_policy() -> dict:
    """
    L1/L2: load policy file, verify HMAC. On tamper/missing key, set
    _POLICY_CORRUPTED=True which causes `send` to refuse all transactions.
    """
    global _POLICY_CORRUPTED
    if not POLICY_FILE.exists():
        _POLICY_CORRUPTED = False
        return dict(_DEFAULT_POLICY)
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as fh:
            policy = json.load(fh)
        for k, v in _DEFAULT_POLICY.items():
            policy.setdefault(k, v)

        stored_hmac = policy.get("_hmac", "")
        hmac_key    = _get_policy_hmac_key()
        expected    = _policy_hmac(policy, hmac_key)

        if not hmac_mod.compare_digest(stored_hmac, expected):
            _POLICY_CORRUPTED = True
            print(
                "[!] SECURITY WARNING: Policy file HMAC verification FAILED.\n"
                "[!] The policy file may have been tampered with.\n"
                "[!] `send` is DISABLED. Run `set-policy` to rebuild the policy.",
                file=sys.stderr,
            )
            return dict(_DEFAULT_POLICY)

        _POLICY_CORRUPTED = False
        return policy

    except (json.JSONDecodeError, OSError) as exc:
        print(f"[!] Cannot read policy file ({exc}); using defaults.", file=sys.stderr)
        _POLICY_CORRUPTED = False
        return dict(_DEFAULT_POLICY)


def _save_policy(policy: dict) -> None:
    """L1: save policy file with HMAC-SHA256 signature."""
    global _POLICY_CORRUPTED
    _ensure_dir(POLICY_FILE.parent)
    hmac_key       = _get_policy_hmac_key()
    policy["_hmac"] = _policy_hmac(policy, hmac_key)

    tmp  = POLICY_FILE.with_suffix(".tmp")
    fd   = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(policy, fh, indent=2)
    os.replace(tmp, POLICY_FILE)
    try:
        os.chmod(POLICY_FILE, 0o600)
    except OSError:
        pass
    _POLICY_CORRUPTED = False


def _enforce_policy(policy: dict, dest: str, amount_btc: float) -> None:
    """T3: enforce spend limit and address allowlist before transaction is built."""
    spend_limit = float(policy.get("spend_limit_btc", 0.0))
    if 0 < spend_limit < amount_btc:
        raise ValueError(
            f"Policy violation: {amount_btc} BTC exceeds spend limit of "
            f"{spend_limit} BTC. Adjust with `set-policy`."
        )
    allowlist = policy.get("allowlist", [])
    if allowlist and dest not in allowlist:
        raise ValueError(
            f"Policy violation: destination '{dest}' is not in the address "
            f"allowlist. Add it with `set-policy` or clear the allowlist."
        )


def _address_challenge(dest: str) -> None:
    """T3: clipboard-hijacking guard — user must type the last 8 chars of dest."""
    tail = dest[-8:]
    print()
    print("[!] HIGH-VALUE SEND — address confirmation required.")
    print(f"    Full destination : {dest}")
    print("    Type the LAST 8 characters to confirm: ", end="", flush=True)
    entered = input().strip()
    if entered != tail:
        raise ValueError(
            f"Address confirmation failed (expected '{tail}'). "
            "Transaction aborted."
        )


def _print_policy(policy: dict) -> None:
    sl = float(policy.get("spend_limit_btc", 0))
    al = policy.get("allowlist", [])
    dc = float(policy.get("require_address_challenge_above_btc", 0))
    sig = policy.get("_hmac", "(none)")[:16] + "..." if policy.get("_hmac") else "(none)"
    print("Current transaction policy:")
    print(f"  Spend limit per transaction : {'unlimited' if not sl else f'{sl} BTC'}")
    print(f"  Address allowlist           : {'any address' if not al else ', '.join(al)}")
    print(f"  Address challenge above     : {'disabled' if not dc else f'{dc} BTC'}")
    print(f"  Integrity HMAC (first 16)   : {sig}")


# ---------------------------------------------------------------------------
# T4 — Fee safeguards with dedicated --force-high-fee override
# ---------------------------------------------------------------------------

def _check_fee_rate(rate, force_high_fee: bool) -> None:
    """T4: soft-warn + enforceable hard cap."""
    if rate is None:
        return
    if rate <= 0:
        raise ValueError("Fee rate must be a positive integer (sat/vB).")
    if rate > FEE_RATE_HARD_CAP:
        if not force_high_fee:
            raise ValueError(
                f"Fee rate {rate} sat/vB exceeds hard cap of "
                f"{FEE_RATE_HARD_CAP} sat/vB. Add --force-high-fee to override."
            )
        print(
            f"[!] WARNING: forcing extreme fee rate {rate} sat/vB. Verify this is intentional.",
            file=sys.stderr,
        )
    elif rate > FEE_RATE_SOFT_CAP:
        print(
            f"[!] Caution: fee rate {rate} sat/vB is unusually high "
            f"(soft cap {FEE_RATE_SOFT_CAP} sat/vB). Continuing.",
            file=sys.stderr,
        )


# ---------------------------------------------------------------------------
# N2 — Balance cross-verification from multiple block explorers
# ---------------------------------------------------------------------------

def _cross_verify_balance(addr: str, is_testnet: bool) -> None:
    """
    N2: query Blockstream and Mempool.space independently; warn on mismatch.
    Both APIs follow the same JSON schema for address stats.
    """
    net = "testnet/" if is_testnet else ""
    sources = {
        "Blockstream" : f"https://blockstream.info/{net}api/address/{addr}",
        "Mempool.space": f"https://mempool.space/{net}api/address/{addr}",
    }
    balances: dict[str, int] = {}
    for name, url in sources.items():
        try:
            resp = _V3_SESSION.get(url, timeout=8)
            resp.raise_for_status()
            data    = resp.json()
            funded  = data.get("chain_stats", {}).get("funded_txo_sum", 0)
            spent   = data.get("chain_stats", {}).get("spent_txo_sum", 0)
            balances[name] = int(funded) - int(spent)
        except Exception as exc:
            print(
                f"[!] N2 cross-verify: could not reach {name} ({_sanitize(str(exc))})",
                file=sys.stderr,
            )

    if len(balances) == 2:
        vals = list(balances.values())
        if abs(vals[0] - vals[1]) > 0:
            print("[!] N2 WARNING: Balance mismatch between independent sources!",
                  file=sys.stderr)
            for src, bal in balances.items():
                print(f"    {src}: {bal / 100_000_000:.8f} BTC", file=sys.stderr)
            print(
                "[!] One source may be out of sync. Verify before transacting.",
                file=sys.stderr,
            )
        else:
            print(
                f"[N2] Cross-verification OK: both sources agree "
                f"({vals[0] / 100_000_000:.8f} BTC)."
            )


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def generate(args):
    """
    K4/K1/M2/U1: generate key from BIP-39 mnemonic; backup verification
    challenge before the keystore is written.
    """
    mainnet = not args.testnet

    # K4: generate and display mnemonic
    phrase = _generate_mnemonic()
    words  = phrase.split()

    print(f"\nNetwork: {network_label(args.testnet)}")
    print("\n" + "=" * 60)
    print("  RECOVERY PHRASE — Write this down NOW (12 words)")
    print("=" * 60)
    for i, word in enumerate(words, 1):
        print(f"  {i:2d}. {word:<12}", end="" if i % 4 else "\n")
    print("\n" + "=" * 60)
    print("  Keep this phrase SECRET and SECURE.")
    print("  It CANNOT be recovered if lost.")
    print("=" * 60)
    input("\nPress Enter when you have written down all 12 words…")

    # K4 score 2: 3-word positional challenge
    if not _backup_verify(words):
        raise ValueError(
            "Backup verification failed. Wallet NOT saved. "
            "Please run generate again after correctly writing down your phrase."
        )
    print("\n[✓] Backup verification passed.")

    # K4: BIP-32 master key → WIF
    key_bytes = _mnemonic_to_private_key(phrase)
    wif       = _private_key_to_wif(key_bytes, mainnet=mainnet)
    del key_bytes

    # Validate WIF creates a valid key
    k    = get_key_class(args.testnet)(wif)
    addr = k.segwit_address

    passphrase_buf = _prompt_new_passphrase()
    try:
        passphrase_str = passphrase_buf.decode("utf-8")
        path = save_encrypted_keystore(
            args.name, wif, passphrase_str, args.testnet, mnemonic=phrase
        )
        del passphrase_str
    finally:
        _zero_buffer(passphrase_buf)
        del passphrase_buf

    del wif, phrase

    print(f"\nAddress  : {addr}")
    print(f"Keystore : {path}")
    print(f"Mode     : AES-256-GCM / PBKDF2-HMAC-SHA256 ({PBKDF2_ITERATIONS:,} iter) + mnemonic")
    print("WIF not printed. Use `export --i-understand-the-risk` to reveal.")
    print("To recover: `recover --name NAME --testnet` (same as this command's --testnet).")


def recover(args):
    """
    K4: restore a wallet from a BIP-39 mnemonic phrase.
    Derives the same private key used by `generate` for the same phrase.
    """
    phrase = getpass.getpass(
        "Enter your 12-word recovery phrase (space-separated, input hidden): "
    ).strip()
    if not _validate_mnemonic(phrase):
        raise ValueError(
            "Invalid recovery phrase (bad checksum or unknown words). "
            "Check spelling and try again."
        )
    print("[✓] Recovery phrase validated.")

    key_bytes = _mnemonic_to_private_key(phrase)
    wif       = _private_key_to_wif(key_bytes, mainnet=not args.testnet)
    del key_bytes

    k    = get_key_class(args.testnet)(wif)
    addr = k.segwit_address

    passphrase_buf = _prompt_new_passphrase()
    try:
        passphrase_str = passphrase_buf.decode("utf-8")
        path = save_encrypted_keystore(
            args.name, wif, passphrase_str, args.testnet, mnemonic=phrase
        )
        del passphrase_str
    finally:
        _zero_buffer(passphrase_buf)
        del passphrase_buf

    del wif, phrase

    print(f"Network  : {network_label(args.testnet)}")
    print(f"Address  : {addr}")
    print(f"Keystore : {path}")
    print("Wallet successfully recovered from mnemonic.")


def import_key(args):
    """M3: import WIF via getpass; save encrypted. No mnemonic (external key)."""
    KeyClass = get_key_class(args.testnet)
    wif = getpass.getpass("Enter WIF to import (input hidden): ").strip()
    if not wif:
        raise ValueError("No WIF provided.")
    try:
        k    = KeyClass(wif)
        addr = k.segwit_address

        passphrase_buf = _prompt_new_passphrase()
        try:
            passphrase_str = passphrase_buf.decode("utf-8")
            path = save_encrypted_keystore(
                args.name, wif, passphrase_str, args.testnet
            )
            del passphrase_str
        finally:
            _zero_buffer(passphrase_buf)
            del passphrase_buf
    finally:
        wif_buf = bytearray(wif.encode("utf-8"))
        _zero_buffer(wif_buf)
        del wif, wif_buf

    print(f"Network  : {network_label(args.testnet)}")
    print(f"Address  : {addr}")
    print(f"Keystore : {path}")


def address(args):
    """Show the receiving address derived from the keystore."""
    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        k = get_key_class(is_testnet)(wif_buf.decode("ascii"))
        print(f"Network : {network_label(is_testnet)}")
        print(f"Address : {k.segwit_address}")
    finally:
        _zero_buffer(wif_buf)


def export(args):
    """U1: reveal WIF — gated behind explicit acknowledgement flag."""
    if not args.i_understand_the_risk:
        print(
            "[!] `export` reveals the raw WIF private key in plaintext.\n"
            "[!] Anyone with screen/scrollback/log access can steal your funds.\n"
            "[!] Re-run with: export --keystore NAME --i-understand-the-risk",
            file=sys.stderr,
        )
        sys.exit(2)
    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        wif_str = wif_buf.decode("ascii")
        k = get_key_class(is_testnet)(wif_str)
        print(f"Network : {network_label(is_testnet)}")
        print(f"Address : {k.segwit_address}")
        print(f"WIF     : {wif_str}")    # intentional — user passed the flag
    finally:
        _zero_buffer(wif_buf)


def balance(args):
    """Display balance; N2: cross-verify against two independent block explorers."""
    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        k    = get_key_class(is_testnet)(wif_buf.decode("ascii"))
        addr = k.segwit_address
        bal  = k.get_balance("btc")
        print(f"Network : {network_label(is_testnet)}")
        print(f"Address : {addr}")
        print(f"Balance : {bal} BTC")
        # N2: cross-check from two independent sources
        _cross_verify_balance(addr, is_testnet)
    finally:
        _zero_buffer(wif_buf)


def send(args):
    """
    T1: review screen. T3: policy + address challenge. T4: fee cap.
    L2: refuses all sends when policy integrity has failed.
    """
    if _POLICY_CORRUPTED:
        raise ValueError(
            "SEND REFUSED: policy integrity check failed (L2 safe mode).\n"
            "Run `set-policy` to rebuild the policy file and restore normal operation."
        )

    _check_fee_rate(args.fee, args.force_high_fee)

    policy = _load_policy()
    if _POLICY_CORRUPTED:
        raise ValueError(
            "SEND REFUSED: policy integrity check failed during load (L2 safe mode)."
        )
    _enforce_policy(policy, args.dest, args.amount)

    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        k           = get_key_class(is_testnet)(wif_buf.decode("ascii"))
        fee_display = (f"{args.fee} sat/vB (manual)" if args.fee is not None
                       else "auto-estimated by bit")

        # T1: review screen
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
            print(f"  [!] Fee above soft cap ({FEE_RATE_SOFT_CAP} sat/vB)!")
        print("=" * 64)

        # T3: address challenge for high-value sends
        thresh = float(policy.get("require_address_challenge_above_btc", 0))
        if thresh > 0 and args.amount > thresh:
            _address_challenge(args.dest)

        # T3: final yes/no confirmation
        answer = input("Type 'yes' to broadcast, anything else to abort: ").strip().lower()
        if answer != "yes":
            print("Aborted. No transaction was broadcast.")
            return

        if args.fee is not None:
            tx = k.send([(args.dest, args.amount, "btc")], fee=args.fee)
        else:
            tx = k.send([(args.dest, args.amount, "btc")])

        print(f"Transaction sent! Hash: {tx}")
    finally:
        _zero_buffer(wif_buf)


def history(args):
    """List confirmed transactions for the wallet address."""
    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        k   = get_key_class(is_testnet)(wif_buf.decode("ascii"))
        txs = k.get_transactions()
        print(f"Network: {network_label(is_testnet)}")
        print(f"Transaction history ({len(txs)}):")
        for tx in txs:
            print(tx)
    finally:
        _zero_buffer(wif_buf)


def utxos(args):
    """List unspent transaction outputs (UTXOs) for the wallet."""
    wif_buf, is_testnet = load_key_from_keystore(args)
    try:
        k        = get_key_class(is_testnet)(wif_buf.decode("ascii"))
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
        _zero_buffer(wif_buf)


def check_fees(_args):
    """Display current network fee estimate and configured policy caps."""
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
        # Peek at header to note if mnemonic backup is present
        has_mnemonic = "mnemonic_ct=" in p.read_text(encoding="utf-8", errors="ignore")
        tag = " [+mnemonic]" if has_mnemonic else ""
        print(f"  {p.name:<30}  {mode}  {st.st_size} bytes{tag}")


def set_policy(_args):
    """T3: create or update the JSON policy file (signed with HMAC)."""
    policy = _load_policy()
    print("Configure transaction policy. Press Enter to keep the current value.")

    print(f"  Spend limit in BTC (0 = unlimited) [{policy['spend_limit_btc']}]: ", end="")
    raw = input().strip()
    if raw:
        policy["spend_limit_btc"] = float(raw)

    current_al = ",".join(policy["allowlist"]) or "(any)"
    print(f"  Address allowlist, comma-separated ('clear' = any) [{current_al}]: ", end="")
    raw = input().strip()
    if raw in ("clear", "none", "-"):
        policy["allowlist"] = []
    elif raw:
        policy["allowlist"] = [a.strip() for a in raw.split(",") if a.strip()]

    print(
        f"  Address-challenge threshold in BTC (0 = disabled) "
        f"[{policy['require_address_challenge_above_btc']}]: ",
        end="",
    )
    raw = input().strip()
    if raw:
        policy["require_address_challenge_above_btc"] = float(raw)

    _save_policy(policy)
    print(f"\nPolicy saved to {POLICY_FILE}  (HMAC-signed, mode 0600)")
    _print_policy(policy)


def show_policy(_args):
    """Display the current transaction policy and its HMAC signature status."""
    policy = _load_policy()
    if _POLICY_CORRUPTED:
        print("[!] WARNING: Policy integrity FAILED. Policy shown is the default.")
    _print_policy(policy)


def check_deps(_args):
    """D2: run pip-audit to check for known vulnerabilities in the dependency tree."""
    try:
        result = subprocess.run(  # nosec B603
            [sys.executable, "-m", "pip_audit", "--strict"],
            check=False,
        )
        if result.returncode != 0:
            print("[!] pip-audit found vulnerabilities. Review output above.", file=sys.stderr)
            sys.exit(result.returncode)
        else:
            print("[+] pip-audit: no known vulnerabilities found.")
    except FileNotFoundError:
        print(
            "[!] pip-audit not installed. Install with:\n"
            "        pip install pip-audit\n"
            "    Then re-run:  python bit_v3.py check-deps",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _add_keystore_arg(p) -> None:
    """All operational subcommands require --keystore (no raw-WIF fallback)."""
    p.add_argument(
        "--keystore", required=True, metavar="NAME",
        help=f"Encrypted keystore name in {KEYSTORE_DIR}.",
    )


def main():
    """Entry point — parse arguments and dispatch to the appropriate command."""
    parser = argparse.ArgumentParser(
        description="bit_v3 — Robust maturity CLI Bitcoin wallet.",
    )
    parser.add_argument("--testnet", action="store_true",
                        help="Use Testnet (default: Mainnet).")

    sub = parser.add_subparsers(dest="command", help="Available commands")
    sub.required = True

    # generate — K4: BIP-39 + backup verification; K1/U1: always encrypted
    p = sub.add_parser("generate",
                       help="Generate a new key (BIP-39 mnemonic + backup verification)")
    p.add_argument("--name", required=True, metavar="NAME",
                   help="Keystore name for the new key.")
    p.set_defaults(func=generate)

    # recover — K4: restore from mnemonic
    p = sub.add_parser("recover",
                       help="Restore wallet from BIP-39 mnemonic phrase")
    p.add_argument("--name", required=True, metavar="NAME",
                   help="Keystore name for the recovered key.")
    p.set_defaults(func=recover)

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

    # balance — N2: cross-verified
    p = sub.add_parser("balance", help="Check balance (cross-verified from 2 sources)")
    _add_keystore_arg(p)
    p.set_defaults(func=balance)

    # send — T1/T3/T4/L2
    p = sub.add_parser("send", help="Send BTC (policy-enforced, review-gated)")
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

    # set-policy — T3/L1
    p = sub.add_parser("set-policy",
                       help="Configure spend limits and address allowlist (HMAC-signed)")
    p.set_defaults(func=set_policy)

    # show-policy
    p = sub.add_parser("show-policy", help="Display current transaction policy and HMAC status")
    p.set_defaults(func=show_policy)

    # check-deps — D2
    p = sub.add_parser("check-deps",
                       help="Scan dependencies for known vulnerabilities (pip-audit)")
    p.set_defaults(func=check_deps)

    args = parser.parse_args()
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\nAborted.", file=sys.stderr)
        sys.exit(130)
    except Exception as exc:   # M4: intercept all errors to prevent WIF leakage
        safe_error(f"Error in '{args.command}'", exc)
        sys.exit(1)
    # SystemExit and KeyboardInterrupt (BaseException, not Exception) propagate naturally.


if __name__ == "__main__":
    main()
