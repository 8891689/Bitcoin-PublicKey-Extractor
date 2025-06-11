# Blockchain Public Key Extractor

The script connects to a locally running full-node core wallet (or compatible) node, scans a specified range of blocks, and extracts the public keys found in the transactions into a document. Supports multi-threaded execution and is compatible with extracting public keys of currencies such as BTC, ETH, BCH, LTC, DOGE, DASH, and ZEC.

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

Before running the script, you need to modify the rpc_config.json constants in the directory to match your node configuration. If there is no password, please set it in .bitcoin/bitcoin.conf in the BTC Core wallet data directory, the same as the script configuration file., which is usually the same as the wallet password and name:

```
{
  "rpc_host": "127.0.0.1",
  "rpc_port": 8332,
  "rpc_user": "8891689",
  "rpc_password": "1111111111111111111111111111111111111111111111111111",
  "num_workers": 4
}

```
For example, for BTC’s bitcoin.conf configuration, you can directly copy the content to the data directory of the bitcoin.conf document. If that doesn’t work, you have to ask AI.
```

# Maximum links between nodes
maxconnections=300

# Enable the RPC Server
server=1

# Set the RPC username
rpcuser=8891689

# Set the RPC password
rpcpassword=1111111111111111111111111111111111111111111111111111

# (Optional) IP addresses to allow connections
rpcallowip=127.0.0.1

# Wallet running CPU thread
par=8
# BTC Core Wallet Local Exchange Port
rpcport=8332


```

# Install Dependencies
This script requires the requests library. You can install them using pip:
```
pip install requests

or

sudo apt update
sudo apt install libcurl4-openssl-dev
```

Alternatively, save the following as a requirements.txt file:
```
requests
```

Txt
Then run:
```
pip install -r requirements.txt

or

g++ extract_data.cpp -lcurl -pthread -Wall -Wextra -O3 -march=native -o extract_data
```
# How to Run

Run the script using the following command format:
```
python3 extract_data.py <start_block_height> <end_block_height> <output_filename>

or

./extract_data <start_block_height> <end_block_height> <output_filename>

```

Parameters:

<start_block_height>: The block height (integer) where you want to start scanning.

<end_block_height>: The block height (integer) where you want to end scanning (inclusive).

<output_filename>: The name of the text file to save the extracted results (e.g., output_pairs.txt).

Example:

Scan blocks from 100000 to 100100 (inclusive) and save the results to output_pairs.txt:
```
python3 extract_data.py 100000 100100 output_pairs.txt

or

./extract_data 100000 100100 output_pairs.txt

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
Since the public key can generate addresses of multiple currencies, if you need the public key with a balance of all currencies, please go to my other library to search and extract the public key with a balance by yourself.
https://github.com/8891689/Public-key-balance-query

# If you need a finished public key with a balance, please contact me. It is not free. The $50 price includes public keys for 7 currencies with or without balances.

Why do I need to pay? Because I need to get paid. If I keep doing it for free, I won't have enough financial support to develop more programs for everyone to use. Thank you for your understanding and tolerance.
```
-----------------------------------
BTC
8321737 btc.1.898828.txt     all 8321737 public key One sort per line
4903469 btc.5.1.898828.txt   1 USD and above 4903469 public key
148444 btc.9.1.898828.txt    1 BTC or more 148444 public key
-----------------------------------
eth
532588 eth.all.e.txt
1113 eth.19.e.txt
75 eth.21.e.txt
-----------------------------------
bch
5603463 bch.all.c.txt
166581 bch.9.c.txt 1 or more
3852 bch.11.c.txt 100 or more
-----------------------------------
ltc
567323 ltc.all.l.txt
73828 ltc.9.l.txt 1 or more
4537 ltc.11.l.txt 100 or more
-----------------------------------
doge
2323277 doge.all.d.txt
1067554 doge.9.d.txt 1 or more
10837 doge.14.d.txt 100,000 or more
-----------------------------------
dash
371077 dash.all.a.txt
23226 dash.9.a.txt 1 or more
2936 dash.11.a.txt 100 or more
-----------------------------------
zec
64382 zec.all.z.txt
-----------------------------------
```
# Taking the BTC data document as an example, the first part is the public key, the middle part is the address, and the last part is the amount.
```
02a720e54e39b28434a4c55462718a4584db973332a834141b8cad7e52c317f695 34xp4vrocgjym3xr7ycvpfhocnxv4twseo 24859753722971
03ef77c7307b52970194bb6ae0189c87d2b4812b59ad6203a5f0724f5df2f6c4a7 bc1ql49ydapnjafl5t2cp9zqpjwe6pdgmxy98859v2 14057482481017
.
.
032e3311413bc458a9920d81c106e81b878cd6eab1d533e34fe7513edd5734b710 bc1qe6jzdxwgw2yxxu7rgj4dfq3ah5vgu8zgdvc6ql 26393030
.
.
032e4311413bc458a9920d81c106980b877cd6eab1d533e34fe7513edd5734b710 bc1qe6jzdxwgw2yxxu7rgj4dfq3ah5vgu8zgdvc6ql 1
```
or only the public key
```
02a720e54e39b28434a4c55462718a4584db973332a834141b8cad7e52c317f695
03ef77c7307b52970194bb6ae0189c87d2b4812b59ad6203a5f0724f5df2f6c4a7
.
.
032e3311413bc458a9920d81c106e81b878cd6eab1d533e34fe7513edd5734b710
.
.
032e4311413bc458a9920d81c106980b877cd6eab1d533e34fe7513edd5734b719
```
# To retrieve the public key of other balances, you can use ./numerical_classification, where you can specify the amount and type.
```
./numerical_classification

Usage: ./numerical_classification -l <min_digits> [-x] <input_file> <output_file>
  -l <min_digits> : Specifies the minimum number of digits for the amount value (required).
  -x              : Optional. If present, only extract the public key. Otherwise, keep the original data structure.
  <input_file>    : Path to the input data file.
  <output_file>   : Path to the output results file.

Example 1: ./numerical_classification -l 9 -x input.txt output.txt
           (Extracts public keys for amounts with 9 or more digits)
Example 2: ./numerical_classification -l 9 input.txt output.txt
           (Extracts full lines for amounts with 9 or more digits)
```
# This is to remove duplicates and sort by amount.
```           
./dedup_sort

Usage: ./dedup_sort <input_file.txt> <output_file.txt>
          
```
# Sponsorship
If this project was helpful to you, please buy me a coffee. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```

# 📜 Disclaimer

This tool is provided for learning and research purposes only. Please use it with an understanding of the relevant risks. The developers are not responsible for financial losses or legal liability -caused by the use of this tool.
