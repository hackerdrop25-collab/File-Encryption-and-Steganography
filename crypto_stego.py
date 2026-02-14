from cryptography.fernet import Fernet
import os
import io
from PIL import Image
import numpy as np

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

    # Image Steganography Methods (LSB)

    def _message_to_binary(self, message):
        """Convert a string to binary."""
        if type(message) == str:
            return ''.join([format(ord(i), "08b") for i in message])
        elif type(message) == bytes:
            return ''.join([format(i, "08b") for i in message])
        elif type(message) == np.ndarray:
            return [format(i, "08b") for i in message]
        elif type(message) == int or type(message) == np.uint8:
            return format(message, "08b")
        else:
            raise TypeError("Input type not supported")

    def hide_message(self, image_path, message, output_path):
        """Hide a message in an image using LSB steganography."""
        try:
            # Append a delimiter to know when the message ends
            message += "#####"
            
            # Open image
            image = Image.open(image_path)
            # Convert to RGB if not already (handle RGBA, P, etc by converting to RGB, though RGBA support would be better if we want to preserve transparency, strict RGB is safer for basic LSB)
            if image.mode != 'RGB':
                image = image.convert('RGB')
                
            image_array = np.array(image)
            
            # Check if message fits
            max_bytes = (image_array.shape[0] * image_array.shape[1] * 3) // 8
            if len(message) > max_bytes:
                raise ValueError(f"Message too long. Image can hold {max_bytes} characters, but message is {len(message)} characters.")

            binary_message = self._message_to_binary(message)
            data_len = len(binary_message)
            
            flat_image = image_array.flatten()
            
            # Modify the least significant bit
            for i in range(data_len):
                flat_image[i] = (flat_image[i] & 254) | int(binary_message[i])
                
            # Reshape back to image
            encoded_image_array = flat_image.reshape(image_array.shape)
            encoded_image = Image.fromarray(encoded_image_array.astype('uint8'), 'RGB')
            
            # Save the image (must be PNG to be lossless)
            if not output_path.lower().endswith('.png'):
                output_path = os.path.splitext(output_path)[0] + '.png'
                
            encoded_image.save(output_path)
            return output_path

        except Exception as e:
            raise Exception(f"Failed to hide message: {str(e)}")

    def extract_message(self, image_path):
        """Extract a hidden message from an image."""
        try:
            image = Image.open(image_path)
            if image.mode != 'RGB':
                image = image.convert('RGB')
                
            image_array = np.array(image)
            flat_image = image_array.flatten()
            
            binary_data = ""
            for i in range(len(flat_image)):
                binary_data += str(flat_image[i] & 1)

            # Split by 8 bits
            all_bytes = [binary_data[i: i+8] for i in range(0, len(binary_data), 8)]
            
            decoded_data = ""
            for byte in all_bytes:
                decoded_data += chr(int(byte, 2))
                if decoded_data[-5:] == "#####":
                    return decoded_data[:-5]
            
            # If we didn't find the delimiter
            return "No hidden message found (or delimiter missing)"

        except Exception as e:
            raise Exception(f"Failed to extract message: {str(e)}")
 