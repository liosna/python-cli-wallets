#!/usr/bin/env python3
import sys
import os
import argparse
import getpass
import subprocess
from pprint import pprint

# --- SECURITY: Driver Check & Monkeypatch ---
try:
    import pysqlcipher3
    import pysqlcipher3.dbapi2
except ImportError:
    print("CRITICAL ERROR: pysqlcipher3 is not installed or available.", file=sys.stderr)
    print("This wallet requires full SQLCipher database encryption.", file=sys.stderr)
    print("Please ensure the environment is set up correctly (e.g., pip install pysqlcipher3).", file=sys.stderr)
    sys.exit(1)

# Monkeypatch for SQLAlchemy compatibility (guard for deterministic=True)
try:
    # Test if create_function accepts deterministic kwarg
    conn = pysqlcipher3.dbapi2.connect(":memory:")
    try:
        conn.create_function("test", 0, lambda: None, deterministic=True)
    except TypeError:
        # It failed, so we need the patch
        original_connect = pysqlcipher3.dbapi2.connect
        
        class ConnectionProxy:
            def __init__(self, conn):
                self._conn = conn
            def __getattr__(self, name):
                return getattr(self._conn, name)
            def create_function(self, name, n_args, func, *args, **kwargs):
                # Suppress deterministic=True
                kwargs.pop('deterministic', None)
                return self._conn.create_function(name, n_args, func, *args, **kwargs)
        
        def connect_wrapper(*args, **kwargs):
            conn = original_connect(*args, **kwargs)
            return ConnectionProxy(conn)
            
        pysqlcipher3.dbapi2.connect = connect_wrapper
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


# --- SECURITY: Permissions & Encryption ---

def parse_db_path(db_uri):
    """
    Robustly extract filesystem path from URI.
    Handles:
    - path/to/db
    - sqlite:///path/to/db
    - sqlite+pysqlcipher:///path/to/db
    Rejects:
    - :memory:
    - empty
    """
    if '://' in db_uri:
        # Check allowed schemes
        if not (db_uri.startswith('sqlite://') or db_uri.startswith('sqlite+pysqlcipher://')):
             print(f"CRITICAL SECURITY ERROR: Only SQLite file databases are supported (URI: {db_uri}).", file=sys.stderr)
             sys.exit(1)
        
        # Strip scheme
        if db_uri.startswith('sqlite:////'): # Absolute path linux/mac often has 4 slashes? or just 3? schema://host/path. sqlite:///abs/path
            path = db_uri.split('://', 1)[1]
        elif db_uri.startswith('sqlite:///'):
             path = db_uri.split(':///', 1)[1]
        else:
             path = db_uri.split('://', 1)[1]
    else:
        path = db_uri

    if not path or path == ':memory:':
         print("CRITICAL SECURITY ERROR: In-memory or empty databases are strictly forbidden.", file=sys.stderr)
         sys.exit(1)
         
    return os.path.abspath(path)

def check_permissions(db_uri):
    """Strictly enforce 0600/0700 permissions on database path."""
    abs_path = parse_db_path(db_uri)
    db_dir = os.path.dirname(abs_path)
    
    # 1. Check Directory Permissions (0700)
    if os.path.exists(db_dir):
        st = os.stat(db_dir)
        if st.st_mode & 0o777 != 0o700:
            print(f"CRITICAL SECURITY FAILURE: Database directory '{db_dir}' has insecure permissions ({oct(st.st_mode & 0o777)}). Expected 0700.", file=sys.stderr)
            sys.exit(1)
            
    # 2. Check File Permissions (0600)
    if os.path.exists(abs_path):
        st = os.stat(abs_path)
        if st.st_mode & 0o777 != 0o600:
            print(f"CRITICAL SECURITY FAILURE: Database file '{abs_path}' has insecure permissions ({oct(st.st_mode & 0o777)}). Expected 0600.", file=sys.stderr)
            # Re-enforce? No, fail fast as per requirement. CR2 doesn't say "fix it", it says enforce.
            # But remedation said "Fail-fast".
            sys.exit(1)

def verify_encryption_at_rest(db_uri):
    """
    Verify encryption by attempting to open with system sqlite3 CLI.
    This MUST fail for the check to pass.
    """
    abs_path = parse_db_path(db_uri)
    
    if not os.path.exists(abs_path):
        return

    # Use system sqlite3 to read schema
    try:
        # .schema command usually works on unencrypted DBs.
        # If encrypted, it should say "file is not a database" or similar, or just fail.
        # We capture stderr.
        proc = subprocess.run(
            ['sqlite3', abs_path, '.schema'], 
            capture_output=True, 
            text=True
        )
        
        # If return code is 0 AND we see output, it's likely plaintext.
        # But if it's plaintext and empty, .schema is empty.
        # Better check: try a query.
        proc = subprocess.run(
             ['sqlite3', abs_path, 'SELECT count(*) FROM sqlite_master;'],
             capture_output=True,
             text=True
        )
        
        if proc.returncode == 0:
            # It succeeded -> Plaintext!
            print(f"CRITICAL SECURITY FAILURE: Database '{abs_path}' is NOT ENCRYPTED (opened with sqlite3 CLI).", file=sys.stderr)
            sys.exit(1)
            
    except FileNotFoundError:
        print(f"SECURITY ERROR: sqlite3 CLI is required for encryption verification but was not found."
        "Install sqlite3 and retry.", 
        file=sys.stderr
        )
        sys.exit(1)


def get_db_password():
    password = os.environ.get('BITCOINLIB_DB_PASSWORD')
    if not password:
        try:
            password = getpass.getpass("Enter Wallet Database Password: ")
        except KeyboardInterrupt:
            print("")
            sys.exit(1)
    if not password:
        print("Error: Database password is required for encryption. Exiting.", file=sys.stderr)
        sys.exit(1)
    return password


# --- CLW Parity Helpers ---

def exception_handler(exception_type, exception, traceback):
    print("%s: %s" % (exception_type.__name__, exception))

def get_passphrase(strength=128, interactive=False, quiet=False, output_to=sys.stdout):
    passphrase = Mnemonic().generate(strength)
    if not quiet:
        print("Passphrase: %s" % passphrase, file=output_to)
        print("Please backup this key properly, if you lose it all associated funds will be lost!", file=output_to)
        if not interactive:
             # Match CLW input logic exactly
             try:
                resp = input("\nType 'yes' if you understood and backup up your key: ")
                if resp not in ['yes', 'Yes', 'YES']:
                    print("Exiting...")
                    sys.exit()
             except EOFError:
                sys.exit(1)
    return passphrase


# --- Main Logic ---

def main():
    # Enforce secure permissions for all files created by this process
    os.umask(0o077)

    sys.excepthook = exception_handler

    parser = argparse.ArgumentParser(description=f'BitcoinLib CLI Wallet v{BITCOINLIB_VERSION}')
    
    # Global
    parser.add_argument('--database', '-d', default='bitcoinlib.sqlite')
    parser.add_argument('--network', '-n')
    parser.add_argument('--quiet', '-q', action='store_true', help="Quiet mode")
    parser.add_argument('--yes', '-y', action='store_true', help="Non-interactive mode")
    
    subparsers = parser.add_subparsers(dest='command', required=True)

    # WALLET COMMANDS
    
    # Create
    p_create = subparsers.add_parser('wallet-create')
    p_create.add_argument('name')
    p_create.add_argument('--scheme', default='bip32')
    p_create.add_argument('--witness-type', default='segwit')
    p_create.add_argument('--passphrase')
    p_create.add_argument('--passphrase-strength', type=int, default=128)
    p_create.add_argument('--create-from-key', '-c')
    p_create.add_argument('--password') # For BIP38
    p_create.add_argument('--multisig', '-m', nargs='+', help="M N [KEY...]")
    p_create.add_argument('--cosigner-id', '-o', type=int)
    p_create.add_argument('--disable-anti-fee-sniping', action='store_true') # CR2.4
    
    # List
    p_list = subparsers.add_parser('wallet-list')
    
    # Info
    p_info = subparsers.add_parser('wallet-info')
    p_info.add_argument('name')
    
    # Delete
    p_delete = subparsers.add_parser('wallet-delete')
    p_delete.add_argument('name')
    p_delete.add_argument('--force', action='store_true')

    # Empty
    p_empty = subparsers.add_parser('wallet-empty')
    p_empty.add_argument('name')

    # Receive
    p_rec = subparsers.add_parser('wallet-receive')
    p_rec.add_argument('name')
    p_rec.add_argument('--cosigner-id', '-o', type=int)

    # Updates
    p_u_utxo = subparsers.add_parser('wallet-update-utxos')
    p_u_utxo.add_argument('name')
    
    p_u_tx = subparsers.add_parser('wallet-update-txs')
    p_u_tx.add_argument('name')

    # TRANSACTIONS
    
    # Send
    p_send = subparsers.add_parser('tx-send')
    p_send.add_argument('name')
    p_send.add_argument('--send', '-s', nargs=2, action='append', metavar=('ADDRESS', 'AMOUNT'))
    p_send.add_argument('--fee', '-f', type=int)
    p_send.add_argument('--fee-per-kb', '-b', type=int)
    p_send.add_argument('--input-key-id', '-k', type=int)
    p_send.add_argument('--change-outputs', type=int, default=1)
    p_send.add_argument('--push', '-p', action='store_true')
    p_send.add_argument('--rbf', action='store_true')

    # Sweep
    p_sweep = subparsers.add_parser('tx-sweep')
    p_sweep.add_argument('name')
    p_sweep.add_argument('address')
    p_sweep.add_argument('--fee', '-f', type=int)
    p_sweep.add_argument('--fee-per-kb', '-b', type=int)
    p_sweep.add_argument('--push', '-p', action='store_true')
    p_sweep.add_argument('--rbf', action='store_true')

    # Import
    p_imp = subparsers.add_parser('tx-import')
    p_imp.add_argument('name')
    p_imp.add_argument('transaction') # Raw hex or file
    p_imp.add_argument('--push', '-p', action='store_true')

    # KEYS
    
    # Export
    p_exp = subparsers.add_parser('key-export')
    p_exp.add_argument('name')
    
    # Import
    p_k_imp = subparsers.add_parser('key-import')
    p_k_imp.add_argument('name')
    p_k_imp.add_argument('key')

    args = parser.parse_args()

    # --- Setup Output (CR2.3) ---
    output_to = open(os.devnull, 'w') if args.quiet else sys.stdout

    # --- Banner (CR2.2) ---
    if not args.quiet:
        print(f"Command Line Wallet - BitcoinLib {BITCOINLIB_VERSION}", file=output_to)

    # --- Pre-Flight Checks ---
    check_permissions(args.database)
    verify_encryption_at_rest(args.database)
    db_password = get_db_password()

    # --- execution ---
    
    try:
        if args.command == 'wallet-create':
            network = args.network or DEFAULT_NETWORK
            db_path = parse_db_path(args.database)
            if os.path.exists(db_path) and wallet_exists(args.name, db_uri=args.database, db_password=db_password):
                print(f"Wallet '{args.name}' already exists. Choose a different name or delete the existing wallet.", file=output_to)
                sys.exit(1)
                
            print("CREATE wallet '%s' (%s network)" % (args.name, network), file=output_to)
            
            
            anti_fee_sniping = not args.disable_anti_fee_sniping # CR2.4
            
            # 4.2 Multisig logic from CLW
            if args.multisig:
                if len(args.multisig) < 2:
                    raise WalletError("Please enter multisig creation parameter: M N KEY1 KEY2 ...")
                try:
                    sigs_required = int(args.multisig[0])
                    sigs_total = int(args.multisig[1])
                except ValueError:
                    raise WalletError("First two multisig arguments must be integers")
                
                key_list = args.multisig[2:]
                keys_missing = sigs_total - len(key_list)
                
                if keys_missing < 0:
                    raise WalletError("Invalid number of keys (%d required)" % sigs_total)
                
                if keys_missing:
                    print("Not all keys provided, creating %d additional key(s)" % keys_missing, file=output_to)
                    for _ in range(keys_missing):
                        passphrase = get_passphrase(args.passphrase_strength, args.yes, args.quiet, output_to)
                        key_list.append(HDKey.from_passphrase(passphrase, network=network))
                
                w = Wallet.create(args.name, key_list, sigs_required=sigs_required, network=network,
                                  cosigner_id=args.cosigner_id, db_uri=args.database, db_password=db_password,
                                  witness_type=args.witness_type, scheme='multisig',
                                  anti_fee_sniping=anti_fee_sniping)

            # 4.3 Create from key
            elif args.create_from_key:
                import_key = args.create_from_key
                kf = get_key_format(import_key)
                if kf['format'] == 'wif_protected':
                    if not args.password:
                        raise WalletError("This is a WIF protected key, please provide simple --password")
                    import_key, _ = HDKey._bip38_decrypt(import_key, args.password, network, args.witness_type)
                
                w = Wallet.create(args.name, import_key, network=network, db_uri=args.database, 
                                  db_password=db_password, witness_type=args.witness_type,
                                  anti_fee_sniping=anti_fee_sniping)

            # Standard Create
            else:
                passphrase = args.passphrase
                if passphrase is None:
                    passphrase = get_passphrase(args.passphrase_strength, args.yes, args.quiet, output_to)
                
                if len(passphrase.split(' ')) < 3:
                    raise WalletError("Passphrase must be 3 words or more")

                hdkey = HDKey.from_passphrase(passphrase, network=network)
                w = Wallet.create(args.name, hdkey, network=network, witness_type=args.witness_type,
                                  db_uri=args.database, db_password=db_password, password=args.password,
                                  anti_fee_sniping=anti_fee_sniping)

            # Force permissions immediately (fix for umask issues)
            # Use strict parser for path
            # Force permissions immediately (fix for umask issues)
            # Use strict parser for path
            path = parse_db_path(args.database)
            if os.path.exists(path):
                os.chmod(path, 0o600)

            # POST-CREATION SECURITY CHECK
            check_permissions(args.database)
            verify_encryption_at_rest(args.database)
            
            args.wallet_info = True 
            w.info() 

        elif args.command == 'wallet-list':
            print("BitcoinLib wallets:", file=output_to)
            wallets = wallets_list(db_uri=args.database, db_password=db_password)
            if not wallets:
                # CR2.7 Text Match
                print("Use new --help to see available options to create a new wallet.", file=output_to)
            else:
                for w in wallets:
                    if w.get('parent_id'): continue
                    print("[%d] %s (%s) %s" % (w['id'], w['name'], w['network'], w['owner']), file=output_to)

        elif args.command == 'wallet-info':
            # Resolve name or ID
            name_or_id = args.name
            if name_or_id.isdigit():
                 name_or_id = int(name_or_id)
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            print("Wallet info for %s" % w.name, file=output_to)
            w.info()

        elif args.command == 'wallet-delete':
            # CR2.1 Numeric ID support
            name_or_id = args.name
            if name_or_id.isdigit():
                 name_or_id = int(name_or_id)
                
            if not wallet_exists(name_or_id, db_uri=args.database, db_password=db_password):
                 print("Wallet '%s' not found" % args.name, file=output_to)
            else:
                # Resolve object to get name for confirmation if ID was passed
                if isinstance(name_or_id, int):
                    # We need to peek? Or just trust delete?
                    # Parity request: "delete 12 behaves same". CLW confirms vs numeric ID?
                    # CLW: if wallet_name.isdigit(): ... check = input(...) if check not in [args.wallet_name, str(w.wallet_id)]
                    # So we need the wallet object to verify matches name or ID.
                    w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
                    check_target_name = w.name
                    check_target_id = str(w.wallet_id)
                else:
                    check_target_name = name_or_id
                    check_target_id = None # Unknown
                
                if not (args.quiet or args.yes or args.force):
                    inp = input("Wallet '%s' with all keys will be removed.\nPlease retype exact name of wallet to proceed: " % args.name)
                    # CLW logic: check not in [args.wallet_name, str(w.wallet_id)]
                    valid = [args.name]
                    if check_target_name: valid.append(check_target_name)
                    if check_target_id: valid.append(check_target_id)
                    
                    if inp not in valid:
                        print("Specified wallet name incorrect", file=output_to)
                        sys.exit(0)
                
                if wallet_delete(name_or_id, force=True, db_uri=args.database, db_password=db_password):
                    print("Wallet %s has been removed" % args.name, file=output_to)
                else:
                    print("Error when deleting wallet", file=output_to)

        elif args.command == 'wallet-empty':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            wallet_empty(name_or_id, db_uri=args.database, db_password=db_password)
            print("Removed transactions and emptied wallet.", file=output_to)

        elif args.command == 'wallet-receive':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            key = w.get_key(network=args.network or w.network.name, cosigner_id=args.cosigner_id)
            print("Receive address: %s" % key.address, file=output_to)

        elif args.command == 'wallet-update-utxos':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            print("Updating wallet utxo's", file=output_to)
            w.utxos_update()

        elif args.command == 'wallet-update-txs':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            print("Updating wallet transactions", file=output_to)
            w.scan(scan_gap_limit=3)

        elif args.command == 'tx-send':
            if args.fee_per_kb: 
                raise WalletError("Fee-per-kb option not allowed with --send") 
            
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            
            if not args.send:
                raise WalletError("Specify --send ADDRESS AMOUNT")
            
            output_arr = [(addr, val) for (addr, val) in args.send]
            
            t = w.transaction_create(output_arr=output_arr, 
                                     network=args.network or w.network.name, 
                                     fee=args.fee,
                                     min_confirms=0, 
                                     input_key_id=args.input_key_id,
                                     number_of_change_outputs=args.change_outputs,
                                     replace_by_fee=args.rbf) 
            t.sign()
            print("Transaction created", file=output_to)
            t.info()
            
            if args.push:
                t.send()
                if t.pushed:
                    print("Transaction pushed to network. Transaction ID: %s" % t.txid, file=output_to)
                else:
                    print("Error creating transaction: %s" % t.error, file=output_to)
            else:
                print("\nTransaction created but not sent yet. Transaction dictionary for export: ", file=output_to)
                pprint(t.as_dict(), stream=output_to)

        elif args.command == 'tx-sweep':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            print("Sweep wallet. Send all funds to %s" % args.address, file=output_to)
            
            t = w.sweep(args.address, 
                        broadcast=args.push, 
                        network=args.network or w.network.name,
                        fee_per_kb=args.fee_per_kb, 
                        fee=args.fee,
                        replace_by_fee=args.rbf) 
            
            if not t:
                raise WalletError("Error sweeping wallet (empty output?)")
                
            t.info()
            
            if args.push:
                 if t.pushed:
                      print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                 else:
                      print("Error sweeping: %s" % t.error, file=output_to)
            else:
                 print("\nTransaction created but not sent yet. Transaction dictionary for export: ", file=output_to)
                 pprint(t.as_dict(), stream=output_to)

        elif args.command == 'tx-import':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            tx_data = args.transaction
            
            if os.path.exists(tx_data):
                with open(tx_data, 'r') as f:
                    content = f.read().strip()
                import ast
                try:
                     tx_data = ast.literal_eval(content)
                except:
                     tx_data = content
            else:
                 import ast
                 try:
                     tx_data = ast.literal_eval(tx_data)
                 except:
                     pass
            
            if isinstance(tx_data, dict):
                t = w.transaction_import(tx_data)
            else:
                t = w.transaction_import_raw(tx_data, network=args.network or w.network.name)
                
            t.sign()
            
            if args.push:
                if t.send():
                    print("Transaction pushed. ID: %s" % t.txid, file=output_to)
                else:
                    print("Error pushing: %s" % t.error, file=output_to)
            t.info()
            print("Signed transaction:", file=output_to)
            if not args.quiet:
                pprint(t.as_dict(), stream=output_to)

        elif args.command == 'key-export':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            if w.scheme == 'multisig':
                for c in w.cosigner:
                    if c.main_key and c.main_key.is_private:
                        print(c.main_key.wif)
            elif w.main_key and w.main_key.is_private:
                print(w.main_key.wif)
            else:
                print("No private key available", file=output_to)

        elif args.command == 'key-import':
            name_or_id = int(args.name) if args.name.isdigit() else args.name
            w = Wallet(name_or_id, db_uri=args.database, db_password=db_password)
            if w.import_key(args.key):
                print("Private key imported", file=output_to)
            else:
                print("Failed to import key", file=output_to)
                
    except WalletError as e:
        print("WalletError: %s" % e, file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print("Unexpected %s: %s" % (type(e).__name__, e), file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
