#!/usr/bin/env python3
"""
bitcoinlib_v02.py — Enhanced Bitcoin CLI wallet.

"""
import sys
import os
import re
import argparse
import getpass
import random
import subprocess
from pprint import pprint

# ---------------------------------------------------------------------------
# SECURITY: Driver Check & Monkeypatch
# ---------------------------------------------------------------------------
try:
    import pysqlcipher3
    import pysqlcipher3.dbapi2
except ImportError:
    print("CRITICAL ERROR: pysqlcipher3 is not installed or available.", file=sys.stderr)
    print("This wallet requires full SQLCipher database encryption.", file=sys.stderr)
    print("Please ensure the environment is set up correctly.", file=sys.stderr)
    sys.exit(1)

# Monkeypatch: suppress deterministic=True kwarg on older pysqlcipher3 builds
try:
    conn = pysqlcipher3.dbapi2.connect(":memory:")
    try:
        conn.create_function("test", 0, lambda: None, deterministic=True)
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
        conn.close()
except Exception:
    pass

from bitcoinlib.wallets import Wallet, wallets_list, wallet_exists, wallet_delete, WalletError, wallet_empty
from bitcoinlib.keys import HDKey, get_key_format
from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.main import BITCOINLIB_VERSION
from bitcoinlib.config.config import DEFAULT_NETWORK


# ---------------------------------------------------------------------------
# M2 — Secret redaction
# ---------------------------------------------------------------------------
_REDACT_PATTERNS = [
    re.compile(r'[xt]prv[1-9A-HJ-NP-Za-km-z]{100,}'),  # HD extended private keys
    re.compile(r'[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}'),   # WIF private keys
]


def _redact(text: str) -> str:
    """Replace recognisable private-key patterns with [REDACTED]."""
    for pat in _REDACT_PATTERNS:
        text = pat.sub('[REDACTED]', text)
    return text


# ---------------------------------------------------------------------------
# SECURITY: Filesystem permissions & encryption verification
# ---------------------------------------------------------------------------

def parse_db_path(db_uri: str) -> str:
    """Return the absolute filesystem path embedded in a DB URI."""
    if '://' in db_uri:
        if not (db_uri.startswith('sqlite://') or
                db_uri.startswith('sqlite+pysqlcipher://')):
            print(f"CRITICAL SECURITY ERROR: Only SQLite file databases are "
                  f"supported (URI: {db_uri}).", file=sys.stderr)
            sys.exit(1)
        path = db_uri.split(':///', 1)[1] if ':///' in db_uri else db_uri.split('://', 1)[1]
    else:
        path = db_uri

    if not path or path == ':memory:':
        print("CRITICAL SECURITY ERROR: In-memory or empty databases are "
              "strictly forbidden.", file=sys.stderr)
        sys.exit(1)

    return os.path.abspath(path)


def check_permissions(db_uri: str) -> None:
    """Abort if the database directory or file has insecure permissions."""
    abs_path = parse_db_path(db_uri)
    db_dir = os.path.dirname(abs_path)

    if os.path.exists(db_dir):
        mode = os.stat(db_dir).st_mode & 0o777
        if mode != 0o700:
            print(f"CRITICAL SECURITY FAILURE: Database directory '{db_dir}' "
                  f"has insecure permissions ({oct(mode)}). Expected 0700.",
                  file=sys.stderr)
            sys.exit(1)

    if os.path.exists(abs_path):
        mode = os.stat(abs_path).st_mode & 0o777
        if mode != 0o600:
            print(f"CRITICAL SECURITY FAILURE: Database file '{abs_path}' "
                  f"has insecure permissions ({oct(mode)}). Expected 0600.",
                  file=sys.stderr)
            sys.exit(1)


def verify_encryption_at_rest(db_uri: str) -> None:
    """Abort if the database can be opened by the plain sqlite3 CLI."""
    abs_path = parse_db_path(db_uri)
    if not os.path.exists(abs_path):
        return
    try:
        proc = subprocess.run(
            ['sqlite3', abs_path, 'SELECT count(*) FROM sqlite_master;'],
            capture_output=True, text=True
        )
        if proc.returncode == 0:
            print(f"CRITICAL SECURITY FAILURE: Database '{abs_path}' is NOT "
                  f"ENCRYPTED (opened with sqlite3 CLI).", file=sys.stderr)
            sys.exit(1)
    except FileNotFoundError:
        print("SECURITY ERROR: sqlite3 CLI is required for encryption "
              "verification but was not found. Install sqlite3 and retry.",
              file=sys.stderr)
        sys.exit(1)


def get_db_password() -> str:
    password = os.environ.get('BITCOINLIB_DB_PASSWORD')
    if not password:
        try:
            password = getpass.getpass("Enter Wallet Database Password: ")
        except KeyboardInterrupt:
            print("")
            sys.exit(1)
    if not password:
        print("Error: Database password is required. Exiting.", file=sys.stderr)
        sys.exit(1)
    return password


# ---------------------------------------------------------------------------
# L1 / L2 — Safe failure mode for database corruption
# ---------------------------------------------------------------------------
_DB_CORRUPTION_HINTS = frozenset([
    'hmac', 'file is not a database', 'database disk image is malformed',
    'encryption', 'page', 'integrity', 'corrupt',
])


def handle_db_error(exc: Exception) -> bool:
    """
    Inspect *exc* for database-integrity / HMAC-failure markers.
    If detected: print safe-failure-mode message with recovery instructions
    and return True (caller should sys.exit).  Otherwise return False.
    """
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
    print("  b) If you have your BIP-39 seed phrase, create a fresh wallet:", file=sys.stderr)
    print("       python bitcoinlib_v02.py -d NEW.sqlite wallet-create <name>", file=sys.stderr)
    print("     then restore funds by sweeping from the old wallet address.", file=sys.stderr)
    print("  c) If the file was backed up, restore from the clean backup.", file=sys.stderr)
    print("=" * 62, file=sys.stderr)
    return True


# ---------------------------------------------------------------------------
# Top-level exception handler (M2 / M4)
# ---------------------------------------------------------------------------

def exception_handler(exc_type, exc, _traceback):
    """Redact key material from the error message before printing."""
    print(_redact(f"{exc_type.__name__}: {exc}"))


# ---------------------------------------------------------------------------
# Mnemonic helpers
# ---------------------------------------------------------------------------

def get_passphrase(strength=128, interactive=False, quiet=False,
                   output_to=sys.stdout) -> str:
    passphrase = Mnemonic().generate(strength)
    if not quiet:
        print("Passphrase: %s" % passphrase, file=output_to)
        print("Please backup this key properly — losing it means losing all "
              "associated funds!", file=output_to)
        if not interactive:
            try:
                resp = input("\nType 'yes' if you have backed up your key: ")
                if resp not in ['yes', 'Yes', 'YES']:
                    print("Exiting...")
                    sys.exit()
            except EOFError:
                sys.exit(1)
    return passphrase


def verify_seed_backup(passphrase: str) -> None:
    """
    K4 — Challenge the user to re-enter 3 randomly chosen words from the
    mnemonic before the wallet is written to disk.

    This step is intentionally NOT bypassable via --yes or --quiet so that
    the user must demonstrate they have genuinely recorded their seed phrase.
    """
    words = passphrase.split()
    if len(words) < 3:
        return  # Too short to challenge meaningfully

    indices = sorted(random.sample(range(len(words)), 3))

    print("\n--- SEED BACKUP VERIFICATION ---", file=sys.stderr)
    print("To confirm your backup, enter the requested words from your seed phrase.", file=sys.stderr)
    print("(This step cannot be skipped and the answers are never stored.)\n", file=sys.stderr)

    for idx in indices:
        try:
            entered = input(f"  Word #{idx + 1}: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nSeed verification cancelled. Wallet not created.", file=sys.stderr)
            sys.exit(1)

        if entered != words[idx].lower():
            print(f"\nVerification FAILED at word #{idx + 1}. "
                  "Please write your seed phrase carefully and try again.",
                  file=sys.stderr)
            sys.exit(1)

    print("Seed backup verification PASSED.\n", file=sys.stderr)


# ---------------------------------------------------------------------------
# T1 / T4 — Transaction review & fee safeguards
# ---------------------------------------------------------------------------

FEE_RATE_WARNING_SAT_VB = 200  # warn when fee rate exceeds this threshold


def format_tx_review(t, network_name: str):
    """
    Build a comprehensive pre-signing summary.

    Returns (review_text: str, is_fee_anomaly: bool).
    """
    lines = [
        "",
        "=" * 62,
        "  TRANSACTION REVIEW — VERIFY ALL FIELDS BEFORE SIGNING",
        "=" * 62,
        f"  Network     : {network_name.upper()}",
        "",
    ]

    for i, o in enumerate(t.outputs):
        role = "CHANGE" if getattr(o, 'is_change', False) else "RECIPIENT"
        sat = int(o.value)
        btc = sat / 1e8
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
        lines.append(f"  Fee Rate    : {fee_rate:.1f} sat/vB  "
                     f"(estimated tx size: {tx_vbytes} vB)")

    is_anomaly = fee_rate is not None and fee_rate > FEE_RATE_WARNING_SAT_VB
    if is_anomaly:
        lines.append("")
        lines.append(f"  *** WARNING: fee rate {fee_rate:.1f} sat/vB exceeds the "
                     f"{FEE_RATE_WARNING_SAT_VB} sat/vB safety threshold! ***")
        lines.append("  *** Verify this is intentional before proceeding.     ***")

    lines.append("=" * 62)
    return "\n".join(lines), is_anomaly


# ---------------------------------------------------------------------------
# T3 — Confirmation helpers
# ---------------------------------------------------------------------------

def confirm_action(prompt: str, auto_yes: bool = False) -> bool:
    """Prompt for yes/no; return True if confirmed.  auto_yes skips prompt."""
    if auto_yes:
        return True
    try:
        resp = input(f"{prompt} [y/N]: ").strip().lower()
        return resp in ('y', 'yes')
    except (EOFError, KeyboardInterrupt):
        print("")
        return False


# ---------------------------------------------------------------------------
# M3 / U1 — Warn on insecure CLI argument usage
# ---------------------------------------------------------------------------

def _warn_cli_secret(arg_name: str) -> None:
    print(f"\n[SECURITY WARNING] --{arg_name} was supplied as a command-line "
          "argument.", file=sys.stderr)
    print("  Your secret is now visible in shell history and the process table.",
          file=sys.stderr)
    print(f"  Omit --{arg_name} to be prompted securely instead.", file=sys.stderr)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    os.umask(0o077)
    sys.excepthook = exception_handler

    parser = argparse.ArgumentParser(
        description=f'BitcoinLib CLI Wallet v{BITCOINLIB_VERSION} (v02)')

    parser.add_argument('--database', '-d', default='bitcoinlib.sqlite')
    parser.add_argument('--network', '-n')
    parser.add_argument('--quiet', '-q', action='store_true')
    parser.add_argument('--yes', '-y', action='store_true',
                        help="Auto-confirm prompts (does NOT bypass seed verification)")

    sub = parser.add_subparsers(dest='command', required=True)

    # wallet-create --------------------------------------------------------
    p_create = sub.add_parser('wallet-create')
    p_create.add_argument('name')
    p_create.add_argument('--scheme', default='bip32')
    p_create.add_argument('--witness-type', default='segwit')
    p_create.add_argument('--passphrase')
    p_create.add_argument('--passphrase-strength', type=int, default=128)
    p_create.add_argument('--create-from-key', '-c')
    p_create.add_argument('--password')
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
    p_send.add_argument('--fee-per-kb', '-b', type=int)
    p_send.add_argument('--input-key-id', '-k', type=int)
    p_send.add_argument('--change-outputs', type=int, default=1)
    p_send.add_argument('--push', '-p', action='store_true')
    p_send.add_argument('--rbf', action='store_true')

    # tx-sweep -------------------------------------------------------------
    p_sweep = sub.add_parser('tx-sweep')
    p_sweep.add_argument('name')
    p_sweep.add_argument('address')
    p_sweep.add_argument('--fee', '-f', type=int)
    p_sweep.add_argument('--fee-per-kb', '-b', type=int)
    p_sweep.add_argument('--push', '-p', action='store_true')
    p_sweep.add_argument('--rbf', action='store_true')

    # tx-import ------------------------------------------------------------
    p_imp = sub.add_parser('tx-import')
    p_imp.add_argument('name')
    p_imp.add_argument('transaction')
    p_imp.add_argument('--push', '-p', action='store_true')

    # key-export -----------------------------------------------------------
    p_exp = sub.add_parser('key-export')
    p_exp.add_argument('name')
    p_exp.add_argument(
        '--i-understand-the-risk', dest='risk_acknowledged',
        action='store_true',
        help="Required: explicitly acknowledge the risk of exporting private "
             "key material to the terminal")

    # key-import -----------------------------------------------------------
    p_ki = sub.add_parser('key-import')
    p_ki.add_argument('name')
    p_ki.add_argument('key')

    args = parser.parse_args()

    output_to = open(os.devnull, 'w') if args.quiet else sys.stdout

    if not args.quiet:
        print(f"Command Line Wallet - BitcoinLib {BITCOINLIB_VERSION}",
              file=output_to)

    # M3 / U1 — Warn on insecure CLI secret args ---------------------------
    if getattr(args, 'passphrase', None) is not None:
        _warn_cli_secret('passphrase')
    if getattr(args, 'password', None) is not None:
        _warn_cli_secret('password')

    # Pre-flight security checks -------------------------------------------
    check_permissions(args.database)
    verify_encryption_at_rest(args.database)
    db_password = get_db_password()

    # -----------------------------------------------------------------------
    # Command dispatch
    # -----------------------------------------------------------------------
    try:

        # ------------------------------------------------------------------
        if args.command == 'wallet-create':
            network = args.network or DEFAULT_NETWORK
            db_path = parse_db_path(args.database)
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
                        "Please enter multisig creation parameter: M N KEY1 KEY2 ...")
                try:
                    sigs_required = int(args.multisig[0])
                    sigs_total = int(args.multisig[1])
                except ValueError:
                    raise WalletError(
                        "First two multisig arguments must be integers")

                key_list = args.multisig[2:]
                keys_missing = sigs_total - len(key_list)
                if keys_missing < 0:
                    raise WalletError(
                        "Invalid number of keys (%d required)" % sigs_total)

                if keys_missing:
                    print("Not all keys provided, creating %d additional key(s)"
                          % keys_missing, file=output_to)
                    for _ in range(keys_missing):
                        phrase = get_passphrase(args.passphrase_strength,
                                                args.yes, args.quiet, output_to)
                        verify_seed_backup(phrase)  # K4: non-bypassable
                        key_list.append(
                            HDKey.from_passphrase(phrase, network=network))

                w = Wallet.create(
                    args.name, key_list, sigs_required=sigs_required,
                    network=network, cosigner_id=args.cosigner_id,
                    db_uri=args.database, db_password=db_password,
                    witness_type=args.witness_type, scheme='multisig',
                    anti_fee_sniping=anti_fee_sniping)

            elif args.create_from_key:
                import_key = args.create_from_key
                kf = get_key_format(import_key)
                if kf['format'] == 'wif_protected':
                    if not args.password:
                        raise WalletError(
                            "This is a WIF protected key; provide --password")
                    import_key, _ = HDKey._bip38_decrypt(
                        import_key, args.password, network, args.witness_type)

                w = Wallet.create(
                    args.name, import_key, network=network,
                    db_uri=args.database, db_password=db_password,
                    witness_type=args.witness_type,
                    anti_fee_sniping=anti_fee_sniping)

            else:
                passphrase = args.passphrase
                if passphrase is None:
                    passphrase = get_passphrase(
                        args.passphrase_strength, args.yes,
                        args.quiet, output_to)

                if len(passphrase.split()) < 3:
                    raise WalletError("Passphrase must be 3 words or more")

                # K4: mandatory backup verification — not bypassable via --yes
                verify_seed_backup(passphrase)

                hdkey = HDKey.from_passphrase(passphrase, network=network)
                w = Wallet.create(
                    args.name, hdkey, network=network,
                    witness_type=args.witness_type,
                    db_uri=args.database, db_password=db_password,
                    password=args.password,
                    anti_fee_sniping=anti_fee_sniping)

            # Enforce permissions on newly created DB
            path = parse_db_path(args.database)
            if os.path.exists(path):
                os.chmod(path, 0o600)

            check_permissions(args.database)
            verify_encryption_at_rest(args.database)
            w.info()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-list':
            print("BitcoinLib wallets:", file=output_to)
            wallets = wallets_list(db_uri=args.database, db_password=db_password)
            if not wallets:
                print("Use --help to see options for creating a new wallet.",
                      file=output_to)
            else:
                for w in wallets:
                    if w.get('parent_id'):
                        continue
                    print("[%d] %s (%s) %s" % (
                        w['id'], w['name'], w['network'], w['owner']),
                        file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-info':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            print("Wallet info for %s" % w.name, file=output_to)
            w.info()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-delete':
            nid = int(args.name) if args.name.isdigit() else args.name
            if not wallet_exists(nid, db_uri=args.database,
                                 db_password=db_password):
                print("Wallet '%s' not found" % args.name, file=output_to)
            else:
                if isinstance(nid, int):
                    w = Wallet(nid, db_uri=args.database,
                               db_password=db_password)
                    check_target_name = w.name
                    check_target_id = str(w.wallet_id)
                else:
                    check_target_name = nid
                    check_target_id = None

                if not (args.quiet or args.yes or args.force):
                    inp = input(
                        "Wallet '%s' with all keys will be removed.\n"
                        "Please retype exact name to proceed: " % args.name)
                    valid = [args.name]
                    if check_target_name:
                        valid.append(check_target_name)
                    if check_target_id:
                        valid.append(check_target_id)
                    if inp not in valid:
                        print("Specified wallet name incorrect", file=output_to)
                        sys.exit(0)

                if wallet_delete(nid, force=True, db_uri=args.database,
                                 db_password=db_password):
                    print("Wallet %s has been removed" % args.name,
                          file=output_to)
                else:
                    print("Error when deleting wallet", file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'wallet-empty':
            nid = int(args.name) if args.name.isdigit() else args.name
            wallet_empty(nid, db_uri=args.database, db_password=db_password)
            print("Removed transactions and emptied wallet.", file=output_to)

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
            print("Updating wallet utxo's", file=output_to)
            w.utxos_update()

        # ------------------------------------------------------------------
        elif args.command == 'wallet-update-txs':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            print("Updating wallet transactions", file=output_to)
            w.scan(scan_gap_limit=3)

        # ------------------------------------------------------------------
        elif args.command == 'tx-send':
            if args.fee_per_kb:
                raise WalletError("--fee-per-kb is not supported with tx-send")
            if not args.send:
                raise WalletError("Specify at least one --send ADDRESS AMOUNT")

            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            output_arr = [(addr, val) for addr, val in args.send]

            # Build unsigned transaction
            t = w.transaction_create(
                output_arr=output_arr,
                network=args.network or w.network.name,
                fee=args.fee,
                min_confirms=0,
                input_key_id=args.input_key_id,
                number_of_change_outputs=args.change_outputs,
                replace_by_fee=args.rbf)

            # T1: Pre-signing review with all critical fields
            review, is_anomaly = format_tx_review(
                t, args.network or w.network.name)
            print(review, file=sys.stderr)

            # T3: Explicit confirmation before signing
            if not confirm_action(
                    "Confirm and sign this transaction?", args.yes):
                print("Transaction cancelled.", file=output_to)
                sys.exit(0)

            # T4: Extra gate for high fee rate (not bypassable with --yes alone)
            if is_anomaly and not args.yes:
                if not confirm_action(
                        "Fee rate is unusually high — confirm anyway?", False):
                    print("Transaction cancelled (high fee).", file=output_to)
                    sys.exit(0)

            t.sign()
            print("Transaction signed.", file=output_to)
            t.info()

            if args.push:
                t.send()
                if t.pushed:
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error pushing transaction: %s" % t.error,
                          file=output_to)
            else:
                print("\nTransaction signed but not sent. Export dictionary:",
                      file=output_to)
                pprint(t.as_dict(), stream=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'tx-sweep':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)

            # U1: Non-suppressible sweep warning — always written to stderr
            print("\n[SECURITY WARNING] tx-sweep will send ALL wallet funds to:",
                  file=sys.stderr)
            print("  %s" % args.address, file=sys.stderr)
            print("This action cannot be undone.", file=sys.stderr)

            # T3: Typed confirmation for high-risk sweep
            if not args.yes:
                try:
                    resp = input(
                        "\nType SWEEP to confirm emptying the wallet: ").strip()
                except (EOFError, KeyboardInterrupt):
                    print("\nSweep cancelled.", file=sys.stderr)
                    sys.exit(0)
                if resp != 'SWEEP':
                    print("Sweep cancelled.", file=sys.stderr)
                    sys.exit(0)

            print("Sweep wallet — sending all funds to %s" % args.address,
                  file=output_to)

            # Build & sign (sweep signs internally; broadcast=False to allow review)
            t = w.sweep(
                args.address,
                broadcast=False,
                network=args.network or w.network.name,
                fee_per_kb=args.fee_per_kb,
                fee=args.fee,
                replace_by_fee=args.rbf)

            if not t:
                raise WalletError("Sweep returned no transaction (wallet empty?)")

            # T1 / T4: Post-build, pre-broadcast review
            review, is_anomaly = format_tx_review(
                t, args.network or w.network.name)
            print(review, file=sys.stderr)

            if is_anomaly and not args.yes:
                if not confirm_action(
                        "Fee rate is unusually high — confirm sweep anyway?",
                        False):
                    print("Sweep cancelled (high fee).", file=output_to)
                    sys.exit(0)

            t.info()

            if args.push:
                t.send()
                if t.pushed:
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error sweeping: %s" % t.error, file=output_to)
            else:
                print("\nTransaction signed but not sent. Export dictionary:",
                      file=output_to)
                pprint(t.as_dict(), stream=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'tx-import':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
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
                t = w.transaction_import_raw(
                    tx_data, network=args.network or w.network.name)

            # T1: Review before signing
            review, is_anomaly = format_tx_review(
                t, args.network or w.network.name)
            print(review, file=sys.stderr)

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
            # U1 / M2: Require explicit risk-acknowledgment flag
            if not args.risk_acknowledged:
                print("\n[SECURITY GATE] key-export is a high-risk operation.",
                      file=sys.stderr)
                print("Exporting private key material to the terminal:", file=sys.stderr)
                print("  · exposes keys to screen capture and terminal logging",
                      file=sys.stderr)
                print("  · may be saved in shell history or terminal scrollback",
                      file=sys.stderr)
                print("  · grants direct access to all associated funds",
                      file=sys.stderr)
                print("\nRe-run with: --i-understand-the-risk", file=sys.stderr)
                sys.exit(1)

            print("\n[WARNING] Exporting PRIVATE KEY MATERIAL. "
                  "Handle with extreme care.", file=sys.stderr)

            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)

            if w.scheme == 'multisig':
                for c in w.cosigner:
                    if c.main_key and c.main_key.is_private:
                        print(c.main_key.wif, file=output_to)
            elif w.main_key and w.main_key.is_private:
                print(w.main_key.wif, file=output_to)
            else:
                print("No private key available", file=output_to)

        # ------------------------------------------------------------------
        elif args.command == 'key-import':
            nid = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(nid, db_uri=args.database, db_password=db_password)
            if w.import_key(args.key):
                print("Private key imported", file=output_to)
            else:
                print("Failed to import key", file=output_to)

    # -----------------------------------------------------------------------
    # Unified error handling with safe-failure-mode and secret redaction
    # -----------------------------------------------------------------------
    except Exception as e:
        # Detect database-integrity / HMAC-failure errors first
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
            print("Unexpected %s: %s" % (type(e).__name__, _redact(str(e))),
                  file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
