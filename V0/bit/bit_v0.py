import argparse
from bit import Key, PrivateKeyTestnet
from bit.network import fees

def get_key_class(is_testnet):
    """Returns the appropriate Key class based on network selection."""
    return PrivateKeyTestnet if is_testnet else Key

def generate(args):
    """Generates a new key and prints address and WIF."""
    KeyClass = get_key_class(args.testnet)
    k = KeyClass()
    print(f"Address: {k.segwit_address}")
    print(f"WIF: {k.to_wif()}")

def import_key(args):
    """Imports a WIF key and prints address and balance."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        print(f"Address: {k.segwit_address}")
        print(f"Balance: {k.get_balance('btc')} BTC")
    except Exception as e:
        print(f"Error importing key: {e}")

def address(args):
    """Generates receiving address from WIF."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        print(f"Address: {k.segwit_address}")
    except Exception as e:
        print(f"Error generating address: {e}")

def export(args):
    """Exports (prints) the WIF key."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        print(f"WIF: {k.to_wif()}")
    except Exception as e:
        print(f"Error exporting key: {e}")

def balance(args):
    """Checks balance for a WIF key."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        print(f"Balance: {k.get_balance('btc')} BTC")
    except Exception as e:
        print(f"Error checking balance: {e}")

def send(args):
    """Sends transactions."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        # bit library handles fee estimation and utxo selection automatically
        tx_hash = k.send([(args.dest, args.amount, 'btc')])
        print(f"Transaction sent! Hash: {tx_hash}")
    except Exception as e:
        print(f"Error sending transaction: {e}")

def history(args):
    """View transaction history."""
    try:
        KeyClass = get_key_class(args.testnet)
        k = KeyClass(args.wif)
        txs = k.get_transactions()
        print(f"Transaction History ({len(txs)}):")
        for tx in txs:
            print(tx)
    except Exception as e:
        print(f"Error fetching history: {e}")

def utxos(args):
	"""Display available UTXOs."""
	try:
		KeyClass = get_key_class(args.testnet)
		k = KeyClass(args.wif)
		unspents = k.get_unspents()
		if not unspents:
			print("No UTXOs available.")
			return
		print(f"Available UTXOs ({len(unspents)}):")
		for idx, utxo in enumerate(unspents, 1):
			print(f"  #{idx} - {utxo.amount} sat ({utxo.amount / 100_000_000} BTC) - {utxo.confirmations} confirmations")
	except Exception as e:
		print(f"Error fetching UTXOs: {e}")

def check_fees(args):
    """Check current network fees."""
    # Fees are generally network independent for estimation in bit, 
    try:
        print(f"Fastest Fee: {fees.get_fee_cached()} sat/byte")
    except Exception as e:
        print(f"Error checking fees: {e}")


def main():
    parser = argparse.ArgumentParser(description="Python CLI Bitcoin Wallet using bit library")
    
    # Global arguments
    parser.add_argument('--testnet', action='store_true', help="Use Testnet (default is Mainnet)")

    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    subparsers.required = True

    # generate
    parser_gen = subparsers.add_parser('generate', help='Generate a new address')
    parser_gen.set_defaults(func=generate)

    # import
    parser_imp = subparsers.add_parser('import', help='Import key from WIF')
    parser_imp.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_imp.set_defaults(func=import_key)

    # address
    parser_addr = subparsers.add_parser('address', help='Get receiving address from WIF')
    parser_addr.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_addr.set_defaults(func=address)

    # export
    parser_exp = subparsers.add_parser('export', help='Export WIF key')
    parser_exp.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_exp.set_defaults(func=export)

    # balance
    parser_bal = subparsers.add_parser('balance', help='Check balance')
    parser_bal.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_bal.set_defaults(func=balance)

    # send
    parser_send = subparsers.add_parser('send', help='Send BTC')
    parser_send.add_argument('wif', help='Sender Wallet Import Format (WIF) key')
    parser_send.add_argument('dest', help='Destination address')
    parser_send.add_argument('amount', type=float, help='Amount in BTC')
    parser_send.set_defaults(func=send)

    # history
    parser_hist = subparsers.add_parser('history', help='View transaction history')
    parser_hist.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_hist.set_defaults(func=history)

    # utxos
    parser_utxos = subparsers.add_parser('utxos', help='Display available UTXOs')
    parser_utxos.add_argument('wif', help='Wallet Import Format (WIF) key')
    parser_utxos.set_defaults(func=utxos)

    # fees
    parser_fees = subparsers.add_parser('fees', help='Check network fees')
    parser_fees.set_defaults(func=check_fees)

    # Parse known args to separate global flags from subcommand args if mixed
    # But with simple argparse, global args must come BEFORE subcommand.
    args = parser.parse_args()
    
    if hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
