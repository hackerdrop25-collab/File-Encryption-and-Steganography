from crypto_stego import CryptoStego
import os
import argparse

def main():
    parser = argparse.ArgumentParser(description="CryptoStego: A tool for encryption and steganography.")
    parser.add_argument('choice', type=str, help="The action to perform (1-5). 1: generate_key, 2: encrypt, 3: decrypt, 4: hide_message, 5: extract_message")
    parser.add_argument('--input-file', type=str, help="Path to the input file.")
    parser.add_argument('--output-file', type=str, help="Path to the output file.")
    parser.add_argument('--message', type=str, help="Message to hide in a text file.")

    args = parser.parse_args()

    cs = CryptoStego()
    key_filename = "encryption.key"
    choice = args.choice

    if choice == '1':
        try:
            cs.generate_key()
            cs.save_key(key_filename)
            print(f"New key generated and saved to '{key_filename}'")
        except Exception as e:
            print(f"Error: {e}")

    elif choice in ['2', '3', '4', '5']:
        if not os.path.exists(key_filename):
            print(f"Error: Key file '{key_filename}' not found. Please generate a key first (Option 1).")
            return
        try:
            cs.load_key(key_filename)
        except Exception as e:
            print(f"Error loading key: {e}")
            return

        if choice == '2':
            if not args.input_file or not args.output_file:
                print("Error: --input-file and --output-file are required for encryption.")
                return
            try:
                cs.encrypt_file(args.input_file, args.output_file)
                print(f"File '{args.input_file}' encrypted successfully to '{args.output_file}'")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '3':
            if not args.input_file or not args.output_file:
                print("Error: --input-file and --output-file are required for decryption.")
                return
            try:
                cs.decrypt_file(args.input_file, args.output_file)
                print(f"File '{args.input_file}' decrypted successfully to '{args.output_file}'")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '4':
            if not args.input_file or not args.message or not args.output_file:
                print("Error: --input-file, --message, and --output-file are required for hiding a message.")
                return
            try:
                cs.hide_message(args.input_file, args.message, args.output_file)
                print(f"Message hidden successfully in '{args.output_file}'")
            except Exception as e:
                print(f"Error: {e}")

        elif choice == '5':
            if not args.input_file:
                print("Error: --input-file is required for extracting a message.")
                return
            try:
                message = cs.extract_message(args.input_file)
                print(f"Extracted message: {message}")
            except Exception as e:
                print(f"Error: {e}")

    else:
        print("Invalid choice. Please enter a number between 1 and 5.")

if __name__ == "__main__":
    main()
