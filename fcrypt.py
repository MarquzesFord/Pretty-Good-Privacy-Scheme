import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public.pem", "wb") as pub_file:
        pub_file.write(public_key)
    
    # Size of the actual key data (in memory, before PEM encoding)
    size_in_bytes = len(private_key)
    print(f"Size of private key data: {size_in_bytes} bytes")

def encrypt_file(public_key_file, input_file, output_file):
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())
        aes_key = get_random_bytes(16)
        iv = get_random_bytes(16)

        rsa_cipher = PKCS1_OAEP.new(public_key)
        encrypted_aes_key = rsa_cipher.encrypt(aes_key)
        with open(input_file, 'rb') as f:
            plaintext = f.read()
        cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
        ciphertext = cipher_aes.encrypt(pad(plaintext, AES.block_size))

        with open(output_file, 'wb') as f:
            f.write(encrypted_aes_key)
            f.write(iv)
            f.write(ciphertext)

def decrypt_file(private_key_file, input_file, output_file):
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    with open(input_file, 'rb') as f:
        encrypted_aes_key = f.read(256)
        print(f"Length of encrypted AES key: {len(encrypted_aes_key)}")  # Add this line to check the length
        if len(encrypted_aes_key) != 256:
            raise ValueError("Encrypted AES key has incorrect length.")
        iv = f.read(16)
        ciphertext = f.read()

    rsa_cipher = PKCS1_OAEP.new(private_key)
    aes_key = rsa_cipher.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher_aes.decrypt(ciphertext), AES.block_size)

    with open(output_file, 'wb') as f:
        f.write(plaintext)

def main():
    parser = argparse.ArgumentParser(description='Encrypt or decrypt a file using RSA and AES.')

    # Create mutually exclusive group for --encrypt and --decrypt
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--encrypt', action='store_true', help='Encrypt the file')
    group.add_argument('--decrypt', action='store_true', help='Decrypt the file')

    # Add remaining arguments
    parser.add_argument('key_file', help='The RSA key file (public key for encryption, private key for decryption)')
    parser.add_argument('input_file', help='The input file for encryption or decryption')
    parser.add_argument('output_file', help='The output file where the result will be saved')

    # Parse the arguments
    args = parser.parse_args()

    # Perform the operation based on the arguments
    if args.encrypt:
        encrypt_file(args.key_file, args.input_file, args.output_file)
        print("Encryption successful.")
    elif args.decrypt:
        decrypt_file(args.key_file, args.input_file, args.output_file)
        print("Decryption successful.")

if __name__ == '__main__':
    main()