# Bitcoin Public Key/Address Extractor

This Python script connects to a locally running Bitcoin (or compatible) node, scans a specified range of blocks, and extracts public keys found within transactions along with their corresponding P2PKH addresses.

## Features

*   **Node Connection**: Connects to a local Bitcoin node via JSON-RPC.
*   **Block Scanning**: Scans blocks within a specified height range.
*   **Data Extraction**: Extracts public keys from transactions (found in `scriptSig` and P2PK outputs).
*   **Address Conversion**: Converts the extracted public keys into their corresponding P2PKH (Pay-to-Public-Key-Hash) Bitcoin addresses.
*   **Result Saving**: Saves the unique `PublicKey: Address` pairs to a specified output file.
*   **Error Handling**: Includes basic RPC connection retry logic and prompts the user for manual reconnection attempts after repeated failures.

## Prerequisites

1.  **Python 3**: Python 3.x must be installed.
2.  **Running Node**: A locally running Bitcoin Core node (or a compatible one) with RPC service enabled.
3.  **RPC Credentials**: The RPC username and password for your node.

## Configuration

Before running the script, you need to modify the following constants at the beginning of the rpc_config.json script to match the configuration of your node. If there is no password, please generate it yourself in the rpcauth.py script in bitcoin/share/rpcauth. It is usually the same as the wallet password and name. :
```python
{
  "rpc_host": "127.0.0.1",
  "rpc_port": 8332,
  "rpc_user": "Your_RPC_Username",
  "rpc_password": "Your_RPC_Password",
  "num_workers": 4
}

```

Note: Hard-coding the RPC password directly into the script will bring certain security risks. Please test it with an empty wallet with no balance. Ensure the script file has appropriate access permissions.

# Install Dependencies
This script requires the requests and base58 libraries. You can install them using pip:

```
pip install requests
```

Alternatively, save the following as a requirements.txt file:
```
requests
```

Txt
Then run:
```
pip install -r requirements.txt
```
# How to Run

Run the script using the following command format:
```
python3 extract_data.py <start_block_height> <end_block_height> <output_filename>
```

Parameters:

<start_block_height>: The block height (integer) where you want to start scanning.

<end_block_height>: The block height (integer) where you want to end scanning (inclusive).

<output_filename>: The name of the text file to save the extracted results (e.g., output_pairs.txt).

Example:

Scan blocks from 100000 to 100100 (inclusive) and save the results to output_pairs.txt:
```
python3 extract_data.py 100000 100100 output_pairs.txt
```

If the script loses connection to the node during execution, it will attempt to reconnect a few times. If it still fails, it will prompt you to press 'P' to manually trigger a reconnection attempt.

# Output File Format
The output file will contain multiple lines, each with the following format:

<Hexadecimal PublicKey>: <Corresponding Bitcoin Address>


Example:
```
02000003446c70bb4082216e6e0a8d905c43804613f40fbb4ef89e1491703d6b6c
02000003cdd1e483d359bbfadb1777f5164108765792198cb8d1a69a16fc61acc7
02000004a91139d2b426760fc930aded2f5fcc3cc86cb0be7bf7735189e3b86821
020000067bb4037be2aa70f5fd152c0e6dfc9457686f6e9808262fa53ee6beb4ba
02000006b9a0307747c4b1f5d02bf2bebcad705352332983697ecb8c9ec2b2b5b8
0200000a5bf7a249717ddb38080de1d43a9b2acaceb6fbcf390ca83a3de98c38e2
0200000a8740c06b9465ca065a54cd74163a59e8ead8b7285d90d4696072247941
0200000b0394e2ac86be288e407c6cadc217307a54c3aedceec5c3d0f6edf29610
0200000b84e04a37aef4228a3fef9ee55b0dc5fa38274c553c0c480b54e9daea97
0200000fa194933ac35c34c18ad659b5c0bb8cc4b21147d66a7721c171e346079d
```
# Since public keys can generate addresses of multiple currencies, if you need all the public keys, please go to my other library, search and extract the public keys with surplus by yourself.
https://github.com/8891689/Public-key-balance-query


# Sponsorship
If this project was helpful to you, please buy me a coffee. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```

# 📜 Disclaimer
Reminder: Do not input real private keys on connected devices!

This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.

