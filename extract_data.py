# author：8891689
import requests
import logging
import json
import sys
import hashlib
import base58
from time import sleep

# RPC Connection Settings
RPC_USER = '8891689'
RPC_PASSWORD = '11111111111111111111111111$ddbbda8cbc8c0a8cc32a84d0590f2de17f1f8dc798c44c701111111111111111111'
RPC_PORT = '8332'
RPC_URL = f'http://127.0.0.1:{RPC_PORT}'

def wait_for_reconnect():
    print("Please press 'P' to reconnect...")
    while True:
        user_input = input().strip().upper()
        if user_input == 'P':
            break

def rpc_request(method, params=None):
    headers = {'Content-Type': 'application/json'}
    payload = {
        "jsonrpc": "1.0",
        "id": "python_rpc",
        "method": method,
        "params": params or []
    }
    for attempt in range(3):
        try:
            response = requests.post(
                RPC_URL,
                auth=(RPC_USER, RPC_PASSWORD),
                headers=headers,
                data=json.dumps(payload),
                timeout=10  # Set timeout
            )
            response_data = response.json()
            if 'error' in response_data and response_data['error']:
                print(f"RPC mistake: {response_data['error']}")
                return None
            return response_data['result']
        except requests.exceptions.RequestException as e:
            print(f"RPC Request failed: {e}")
            sleep(5)  # Wait 5 seconds to try again after failure
    print("All retries have been exhausted")
    wait_for_reconnect()  # Waiting for the user to press 'P' to reconnect
    return rpc_request(method, params)  # Try the request again


def get_block_hash(block_height):
    return rpc_request('getblockhash', [block_height])

def get_block(block_hash):
    return rpc_request('getblock', [block_hash, 2])

def get_transaction(txid):
    return rpc_request('getrawtransaction', [txid, True])

def pubkey_to_address(pubkey_hex):
    if pubkey_hex.startswith('0x'):
        pubkey_hex = pubkey_hex[2:]
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    if len(pubkey_bytes) not in (33, 65):
        return None
    sha256 = hashlib.sha256(pubkey_bytes).digest()
    ripemd160 = hashlib.new('ripemd160', sha256).digest()
    versioned_payload = b'\x00' + ripemd160
    checksum = hashlib.sha256(hashlib.sha256(versioned_payload).digest()).digest()[:4]
    address_bytes = versioned_payload + checksum
    address = base58.b58encode(address_bytes).decode('utf-8')
    return address

def extract_public_keys_from_vin(vin):
    public_keys = []
    if 'scriptSig' in vin and 'asm' in vin['scriptSig']:
        scriptSig_asm = vin['scriptSig']['asm']
        parts = scriptSig_asm.split()
        if len(parts) > 1:
            pubkey_hex = parts[-1]
            if len(pubkey_hex) in [66, 130] and pubkey_hex.startswith(('02', '03', '04')):
                public_keys.append(pubkey_hex)
    return public_keys

def extract_data_from_transaction(tx):
    addresses = []
    public_keys = []

    if not tx:
        return addresses, public_keys

    if 'vin' in tx and len(tx['vin']) > 0 and 'coinbase' in tx['vin'][0]:
        return addresses, public_keys

    for vout in tx.get('vout', []):
        script_pub_key = vout.get('scriptPubKey', {})
        if 'addresses' in script_pub_key:
            addresses.extend(script_pub_key['addresses'])
        elif 'hex' in script_pub_key and script_pub_key.get('type') == 'pubkey':
            public_keys.append(script_pub_key['hex'])
        elif 'type' in script_pub_key and script_pub_key['type'] == 'pubkeyhash':
            addresses.append(script_pub_key['address'])

    for vin in tx.get('vin', []):
        public_keys.extend(extract_public_keys_from_vin(vin))

    return addresses, public_keys

def process_block(block_height, file_handle, seen):
    block_hash = get_block_hash(block_height)
    if not block_hash:
        return
    
    block = get_block(block_hash)
    if not block:
        return

    transactions = block.get('tx', [])
    
    for tx in transactions:
        if isinstance(tx, dict):
            txid = tx.get('txid')
        elif isinstance(tx, str):
            txid = tx
        else:
            continue

        if not isinstance(txid, str):
            continue
        
        tx_data = get_transaction(txid)
        if tx_data:
            addresses, public_keys = extract_data_from_transaction(tx_data)
            for pubkey in public_keys:
                address = pubkey_to_address(pubkey)
                if address and (pubkey, address) not in seen:
                    file_handle.write(f"{pubkey}: {address}\n")
                    seen.add((pubkey, address))

def main(start_block, end_block, output_file):
    if start_block < 0 or end_block < start_block:
        print("Error: invalid block range")
        sys.exit(1)

    seen = set()  # Used to store the written public key-address pair

    with open(output_file, 'w') as file_handle:
        current_block = start_block
        while current_block <= end_block:
            process_block(current_block, file_handle, seen)
            current_block += 1

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("usage: python3 extract_data.py <start_block> <end_block> <output_file>")
        sys.exit(1)
    
    start_block = int(sys.argv[1])
    end_block = int(sys.argv[2])
    output_file = sys.argv[3]

    main(start_block, end_block, output_file)
