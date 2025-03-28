# author：8891689
import os

def load_addresses(file_path):
    """Read the BTC address in document 1"""
    with open(file_path, 'r') as file:
        return set(line.strip() for line in file if line.strip())

def extract_matching_pubkeys(addresses, file_path, output_file):
    """Compare the address in document 2 and extract the matching public key"""
    with open(file_path, 'r') as file, open(output_file, 'w') as output:
        for line in file:
            pubkey, btc_address = line.strip().split(': ')
            if btc_address in addresses:
                output.write(pubkey + '\n')

def main():
    # The file path in the directory
    file1_path = 'Rich Address.txt'
    file2_path = 'Public key and address1.840000.txt'
    output_file = 'Rich Public Key.txt'
    
    # Read the address in document 1
    addresses = load_addresses(file1_path)
    
    # Extract the matching public key from document 2
    extract_matching_pubkeys(addresses, file2_path, output_file)
    
    print(f"The public key has been exported to: {output_file}")

if __name__ == '__main__':
    main()

