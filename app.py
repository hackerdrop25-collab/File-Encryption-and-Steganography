from flask import Flask, request, jsonify, send_file, render_template, flash, redirect, url_for
from werkzeug.utils import secure_filename
from crypto_stego import CryptoStego
import os
import uuid
import time
import shutil
import mimetypes
from cryptography.fernet import Fernet

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Change this to a secure secret key
crypto = CryptoStego()

# Configure upload folder
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

def safe_remove(file_path, max_attempts=3):
    """Safely remove a file with retries"""
    for attempt in range(max_attempts):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            return True
        except Exception as e:
            if attempt < max_attempts - 1:
                time.sleep(0.1)  # Wait before retrying
            else:
                print(f"Warning: Could not remove file {file_path}: {str(e)}")
                return False

def safe_send_file(file_path, download_name=None):
    """Safely send a file with cleanup"""
    try:
        response = send_file(
            file_path,
            as_attachment=True,
            download_name=download_name
        )
        return response
    finally:
        # Schedule file cleanup
        safe_remove(file_path)

def allowed_file(filename):
    """Check if the file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'txt'}

def is_text_file(file_path):
    """Check if a file is a text file"""
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
            file.read(1024)
        return True
    except:
        return False

def calculate_required_lines(message_length):
    """Calculate required lines for steganography"""
    bits_per_line = 2
    total_bits = 32 + (message_length * 8)  # 32 bits for length + message bits
    return (total_bits + bits_per_line - 1) // bits_per_line

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/steganography')
def steganography():
    return render_template('steganography.html')

@app.route('/generate_key', methods=['GET', 'POST'])
def generate_key():
    if request.method == 'GET':
        return render_template('generate_key.html')
    
    try:
        key = crypto.generate_key()
        key_filename = os.path.join(app.config['UPLOAD_FOLDER'], 'key.key')
        crypto.save_key(key_filename)
        return send_file(key_filename, as_attachment=True)
    except Exception as e:
        flash(f'Error generating key: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'GET':
        return render_template('encrypt.html')
    
    if 'file' not in request.files or 'key' not in request.files:
        flash('Please select both a file and a key file', 'error')
        return redirect(url_for('encrypt'))
    
    file = request.files['file']
    key_file = request.files['key']
    
    if file.filename == '' or key_file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('encrypt'))
    
    try:
        # Save uploaded files
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(key_file.filename))
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f'encrypted_{secure_filename(file.filename)}')
        
        file.save(file_path)
        key_file.save(key_path)
        
        # Load key
        with open(key_path, 'rb') as f:
            key = f.read()
        crypto.cipher_suite = Fernet(key)
        
        # Encrypt file
        crypto.encrypt_file(file_path, output_path)
        
        # Clean up
        safe_remove(file_path)
        safe_remove(key_path)
        
        return safe_send_file(output_path, f"encrypted_{file.filename}")
    except Exception as e:
        flash(f'Error during encryption: {str(e)}', 'error')
        return redirect(url_for('encrypt'))

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'GET':
        return render_template('decrypt.html')
    
    if 'file' not in request.files or 'key' not in request.files:
        flash('Please select both a file and a key file', 'error')
        return redirect(url_for('decrypt'))
    
    file = request.files['file']
    key_file = request.files['key']
    
    if file.filename == '' or key_file.filename == '':
        flash('No selected file', 'error')
        return redirect(url_for('decrypt'))
    
    try:
        # Save uploaded files
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        key_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(key_file.filename))
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f'decrypted_{secure_filename(file.filename)}')
        
        file.save(file_path)
        key_file.save(key_path)
        
        # Load key
        with open(key_path, 'rb') as f:
            key = f.read()
        crypto.cipher_suite = Fernet(key)
        
        # Decrypt file
        crypto.decrypt_file(file_path, output_path)
        
        # Clean up
        safe_remove(file_path)
        safe_remove(key_path)
        
        return safe_send_file(output_path, f"decrypted_{file.filename}")
    except Exception as e:
        flash(f'Error during decryption: {str(e)}', 'error')
        return redirect(url_for('decrypt'))

@app.route('/hide_message', methods=['POST'])
def hide_message():
    if 'file' not in request.files or 'message' not in request.form:
        flash('No file selected or message provided', 'error')
        return redirect(url_for('steganography'))
    
    file = request.files['file']
    message = request.form['message']
    
    if file.filename == '' or not message:
        flash('No file selected or message provided', 'error')
        return redirect(url_for('steganography'))
    
    if not allowed_file(file.filename):
        flash('Only text files (.txt) are supported', 'error')
        return redirect(url_for('steganography'))
    
    try:
        # Save uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)
        
        # Verify it's a text file
        if not is_text_file(file_path):
            os.remove(file_path)
            flash('The file is not a valid text file', 'error')
            return redirect(url_for('steganography'))
        
        # Hide message
        output_path = os.path.join(app.config['UPLOAD_FOLDER'], f'hidden_{secure_filename(file.filename)}')
        crypto.hide_message(file_path, message, output_path)
        
        # Clean up
        os.remove(file_path)
        
        return send_file(output_path, as_attachment=True)
    except Exception as e:
        flash(f'Failed to hide message: {str(e)}', 'error')
        return redirect(url_for('steganography'))

@app.route('/extract_message', methods=['POST'])
def extract_message():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('steganography'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('steganography'))
    
    if not allowed_file(file.filename):
        flash('Only text files (.txt) are supported', 'error')
        return redirect(url_for('steganography'))
    
    try:
        # Save uploaded file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(file.filename))
        file.save(file_path)
        
        # Verify it's a text file
        if not is_text_file(file_path):
            os.remove(file_path)
            flash('The file is not a valid text file', 'error')
            return redirect(url_for('steganography'))
        
        # Extract message
        message = crypto.extract_message(file_path)
        
        # Clean up
        os.remove(file_path)
        
        return render_template('steganography.html', extracted_message=message)
    except Exception as e:
        flash(f'Failed to extract message: {str(e)}', 'error')
        return redirect(url_for('steganography'))

if __name__ == '__main__':
    app.run(debug=True) 