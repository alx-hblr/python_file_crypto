import os
import argparse
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def derive_key(password, salt):
    """Derive a key from a password and salt using PBKDF2-HMAC-SHA256

    Args:
        password (str): The password to derive the key from
        salt (bytes): The salt to use in the key derivation

    Returns:
        bytes: The derived key
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def encrypt(file_path:str, password:str):
    """Encrypt a file using AES-256-GCM and save the encrypted file

    Args:
        file_path (str): Path to the file to encrypt
        password (str): Password to encrypt the file with
    """

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    encrypted_file_path = file_path + '.encrypted'
    with open(encrypted_file_path, 'wb') as file:
        file.write(salt + nonce + ciphertext)

    print(f"File encrypted and saved as {encrypted_file_path}")

def decrypt(file_path:str, password:str):
    """Decrypt a file using AES-256-GCM and save the decrypted file

    Args:
        file_path (str): Path to the file to decrypt
        password (str): Password to decrypt the file with
    """
    with open(file_path, 'rb') as file:
        data = file.read()

    salt = data[:16]
    nonce = data[16:28]
    ciphertext = data[28:]

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except:
        print("Decryption failed. Incorrect password or corrupted file.")
        return

    decrypted_file_path = file_path[:-10] if file_path.endswith('.encrypted') else file_path + '.decrypted'
    with open(decrypted_file_path, 'wb') as file:
        file.write(plaintext)
    print(f"File decrypted and saved as {decrypted_file_path}")

def main():
    print(f"This script provides a secure way to encrypt and decrypt files using AES-256-GCM with a password-derived key.")
    print(f"Author: Alexander Hübler | https://github.com/alx-hblr\n")
    
    parser = argparse.ArgumentParser(description="Encrypt or decrypt a file using AES-256-GCM")
    parser.add_argument('file', help="Path to the file to encrypt or decrypt")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-e', '--encrypt', action='store_true', help="Encrypt the file")
    group.add_argument('-d', '--decrypt', action='store_true', help="Decrypt the file")
    if not os.path.exists(parser.parse_args().file):
        print(f"ERROR: File not found.")
        return
    args = parser.parse_args()

    if args.encrypt:
        password = getpass.getpass("Enter the password: ")
        password_verify = getpass.getpass("Re-enter the password: ")

        if password != password_verify:
            print("Passwords do not match")
            return
        else:
            encrypt(args.file, password)

    elif args.decrypt:
        password = getpass.getpass("Enter the password: ")
        decrypt(args.file, password)

if __name__ == "__main__":
    main()