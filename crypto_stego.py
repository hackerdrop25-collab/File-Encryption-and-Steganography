from cryptography.fernet import Fernet
import os
import random
import time
import base64
import re

class CryptoStego:
    def __init__(self):
        self.key = None
        self.cipher_suite = None

    def generate_key(self):
        """Generate a new encryption key."""
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        return self.key

    def save_key(self, filename):
        """Save the encryption key to a file."""
        with open(filename, 'wb') as key_file:
            key_file.write(self.key)

    def load_key(self, filename):
        """Load an encryption key from a file."""
        with open(filename, 'rb') as key_file:
            self.key = key_file.read()
            self.cipher_suite = Fernet(self.key)

    def encrypt_file(self, input_file, output_file):
        """Encrypt a file using the loaded key."""
        try:
            with open(input_file, 'rb') as file:
                file_data = file.read()
            encrypted_data = self.cipher_suite.encrypt(file_data)
            with open(output_file, 'wb') as file:
                file.write(encrypted_data)
        except Exception as e:
            raise Exception(f"Encryption failed: {str(e)}")

    def decrypt_file(self, input_file, output_file):
        """Decrypt a file using the loaded key."""
        try:
            with open(input_file, 'rb') as file:
                encrypted_data = file.read()
            decrypted_data = self.cipher_suite.decrypt(encrypted_data)
            with open(output_file, 'wb') as file:
                file.write(decrypted_data)
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def calculate_required_lines(self, message):
        """Calculate the number of lines required to hide a message."""
        try:
            # Convert message to base64 for more efficient storage
            encoded_message = base64.b64encode(message.encode()).decode()
            # Each character needs 1 line
            return len(encoded_message)
        except Exception as e:
            raise ValueError(f"Failed to calculate required lines: {str(e)}")

    def hide_message(self, input_file, message, output_file):
        """Hide a message in a text file using steganography."""
        try:
            # Validate input
            if not message or not isinstance(message, str):
                raise ValueError("Invalid message: Message must be a non-empty string")
            
            if not os.path.exists(input_file):
                raise ValueError(f"Input file not found: {input_file}")

            # Check if file is a text file
            if not self._is_text_file(input_file):
                raise ValueError("Only text files (.txt) are supported for hiding messages")

            # Read the input file
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()

            # Calculate required lines
            required_lines = self.calculate_required_lines(message)
            if len(lines) < required_lines:
                raise ValueError(f"Message is too long for the text file. Required lines: {required_lines}, Available lines: {len(lines)}. Please use a longer text file or a shorter message.")

            # Convert message to base64 for more efficient storage
            encoded_message = base64.b64encode(message.encode()).decode()
            
            # Create modified lines with hidden message
            modified_lines = []
            message_index = 0
            
            for line in lines:
                if message_index < len(encoded_message):
                    # Add the message character with a marker
                    modified_lines.append(line.rstrip() + ' ' + encoded_message[message_index] + '\n')
                    message_index += 1
                else:
                    # Keep original line
                    modified_lines.append(line)

            # Write the modified content to the output file
            with open(output_file, 'w', encoding='utf-8') as file:
                file.writelines(modified_lines)

            # Verify the message can be extracted
            try:
                extracted = self.extract_message(output_file)
                if extracted != message:
                    raise ValueError("Message verification failed - the hidden message could not be properly extracted")
            except Exception as e:
                # If verification fails, clean up the output file
                if os.path.exists(output_file):
                    os.remove(output_file)
                raise ValueError(f"Message verification failed: {str(e)}")

        except Exception as e:
            raise Exception(f"Failed to hide message: {str(e)}")

    def extract_message(self, input_file):
        """Extract a hidden message from a text file."""
        try:
            # Validate input
            if not os.path.exists(input_file):
                raise ValueError(f"Input file not found: {input_file}")

            # Check if file is a text file
            if not self._is_text_file(input_file):
                raise ValueError("Only text files (.txt) are supported for extracting messages")

            # Read the input file
            with open(input_file, 'r', encoding='utf-8', errors='ignore') as file:
                lines = file.readlines()

            # Extract hidden characters
            hidden_chars = []
            for line in lines:
                # Look for the marker pattern (space followed by a character)
                match = re.search(r' (.)$', line.rstrip())
                if match:
                    hidden_chars.append(match.group(1))

            if not hidden_chars:
                raise ValueError("No hidden message found in the file")

            # Convert hidden characters back to message
            encoded_message = ''.join(hidden_chars)
            try:
                message = base64.b64decode(encoded_message).decode()
                return message
            except Exception as e:
                raise ValueError(f"Invalid message format or corrupted data: {str(e)}")

        except Exception as e:
            raise Exception(f"Failed to extract message: {str(e)}")

    def _is_text_file(self, file_path):
        """Check if a file is a text file."""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                # Try to read a small portion of the file
                file.read(1024)
            return True
        except:
            return False 