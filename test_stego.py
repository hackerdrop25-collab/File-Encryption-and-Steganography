from crypto_stego import CryptoStego
import os

def test_steganography():
    # Create test files
    input_file = "test_input.txt"
    output_file = "test_output.txt"
    message = "This is a test message for steganography!"
    
    # Create a test input file with enough lines
    with open(input_file, 'w', encoding='utf-8') as f:
        for i in range(100):
            f.write(f"This is line {i+1} of the test file.\n")
    
    try:
        # Initialize CryptoStego
        stego = CryptoStego()
        
        # Hide message
        print("Hiding message...")
        stego.hide_message(input_file, message, output_file)
        print("Message hidden successfully!")
        
        # Extract message
        print("Extracting message...")
        extracted = stego.extract_message(output_file)
        print("Message extracted successfully!")
        
        # Verify
        print("\nOriginal message:", message)
        print("Extracted message:", extracted)
        print("\nVerification:", "Success!" if message == extracted else "Failed!")
        
    except Exception as e:
        print(f"Error: {str(e)}")
    finally:
        # Cleanup
        for file in [input_file, output_file]:
            if os.path.exists(file):
                os.remove(file)

if __name__ == "__main__":
    test_steganography() 