from crypto_stego import CryptoStego

def main():
    # Initialize the crypto-stego system
    crypto = CryptoStego()
    
    # Generate and save a new key
    key = crypto.generate_key()
    crypto.save_key('secret.key')
    
    # Example 1: Encrypt a file
    print("Example 1: Encrypting a file")
    try:
        crypto.encrypt_file('input.txt', 'encrypted.txt')
        print("File encrypted successfully!")
    except Exception as e:
        print(f"Encryption error: {e}")
    
    # Example 2: Decrypt a file
    print("\nExample 2: Decrypting a file")
    try:
        crypto.decrypt_file('encrypted.txt', 'decrypted.txt')
        print("File decrypted successfully!")
    except Exception as e:
        print(f"Decryption error: {e}")
    
    # Example 3: Hide a message in a text file
    print("\nExample 3: Hiding a message in a text file")
    try:
        message = "This is a secret message!"
        crypto.hide_message('input.txt', message, 'stego.txt')
        print("Message hidden successfully!")
    except Exception as e:
        print(f"Steganography error: {e}")
    
    # Example 4: Extract a hidden message
    print("\nExample 4: Extracting a hidden message")
    try:
        extracted_message = crypto.extract_message('stego.txt')
        print(f"Extracted message: {extracted_message}")
    except Exception as e:
        print(f"Extraction error: {e}")

if __name__ == "__main__":
    main() 