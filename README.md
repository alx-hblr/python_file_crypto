# File Encryption/Decryption Script

## Overview

This Python script provides a secure way to encrypt and decrypt files using AES-256-GCM (Galois/Counter Mode) with a password-derived key. It uses the `cryptography` library to implement robust encryption and decryption functionality.

## Features

- Encrypt files using AES-256-GCM
- Decrypt previously encrypted files
- Password-based key derivation using PBKDF2-HMAC-SHA256
- Command-line interface for easy use

## Dependencies

- Python 3.x
- `cryptography` library

## Usage

The script can be run from the command line with the following syntax:

```
python script_name.py [-h] (-e | -d) file
```

### Arguments

- `file`: Path to the file to encrypt or decrypt
- `-e`, `--encrypt`: Encrypt the specified file
- `-d`, `--decrypt`: Decrypt the specified file
- `-h`, `--help`: Show help message and exit

## Functionality

### Key Derivation

The `derive_key` function uses PBKDF2-HMAC-SHA256 to derive a 32-byte key from the user's password and a random salt. This process helps protect against brute-force and rainbow table attacks.

### Encryption

The `encrypt` function:
1. Reads the contents of the specified file
2. Generates a random salt and nonce
3. Derives an encryption key using the password and salt
4. Encrypts the file contents using AES-256-GCM
5. Saves the encrypted data (salt + nonce + ciphertext) to a new file with the `.encrypted` extension

### Decryption

The `decrypt` function:
1. Reads the encrypted file
2. Extracts the salt, nonce, and ciphertext
3. Derives the decryption key using the provided password and extracted salt
4. Attempts to decrypt the ciphertext
5. If successful, saves the decrypted data to a new file, removing the `.encrypted` extension if present

## Security Features

- Uses AES-256-GCM, a highly secure encryption algorithm
- Implements key stretching with PBKDF2-HMAC-SHA256 (100,000 iterations)
- Uses unique salt for each encryption to prevent rainbow table attacks
- Employs nonce (number used once) to ensure unique ciphertexts even for identical plaintexts

## Error Handling

- Checks for file existence before processing
- Verifies password match during encryption
- Handles decryption failures due to incorrect passwords or corrupted files

## Limitations

- Does not securely erase the original file after encryption
- Stores the encrypted file in the same directory as the original
- No built-in key management system; users must remember their passwords

## Author

Alexander Hübler | https://github.com/alx-hblr

## Disclaimer

This script is provided for educational purposes. While it implements strong encryption, proper key management and overall system security are crucial for protecting sensitive data.
