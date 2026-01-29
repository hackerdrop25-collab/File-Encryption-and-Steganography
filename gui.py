import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_stego import CryptoStego
import os

class CryptoStegoGUI:
    def __init__(self, master):
        self.master = master
        master.title("CryptoStego")

        self.cs = CryptoStego()
        self.key_filename = "encryption.key"

        # --- Widgets ---
        self.main_frame = tk.Frame(master, padx=10, pady=10)
        self.main_frame.pack()

        # Key Management
        key_frame = tk.LabelFrame(self.main_frame, text="Key Management", padx=10, pady=10)
        key_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=5)
        self.generate_key_button = tk.Button(key_frame, text="Generate and Save Key", command=self.generate_key)
        self.generate_key_button.pack()

        # File Operations
        file_op_frame = tk.LabelFrame(self.main_frame, text="File Operations", padx=10, pady=10)
        file_op_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)

        self.input_file_label = tk.Label(file_op_frame, text="Input File:")
        self.input_file_label.grid(row=0, column=0, sticky="w")
        self.input_file_entry = tk.Entry(file_op_frame, width=50)
        self.input_file_entry.grid(row=0, column=1)
        self.input_file_button = tk.Button(file_op_frame, text="Browse...", command=self.browse_input_file)
        self.input_file_button.grid(row=0, column=2)

        self.output_file_label = tk.Label(file_op_frame, text="Output File:")
        self.output_file_label.grid(row=1, column=0, sticky="w")
        self.output_file_entry = tk.Entry(file_op_frame, width=50)
        self.output_file_entry.grid(row=1, column=1)
        self.output_file_button = tk.Button(file_op_frame, text="Browse...", command=self.browse_output_file)
        self.output_file_button.grid(row=1, column=2)

        self.encrypt_button = tk.Button(file_op_frame, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.grid(row=2, column=0, pady=5)
        self.decrypt_button = tk.Button(file_op_frame, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.grid(row=2, column=1, pady=5)

        # Steganography
        stego_frame = tk.LabelFrame(self.main_frame, text="Steganography", padx=10, pady=10)
        stego_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=5)

        self.message_label = tk.Label(stego_frame, text="Message:")
        self.message_label.grid(row=0, column=0, sticky="w")
        self.message_entry = tk.Entry(stego_frame, width=50)
        self.message_entry.grid(row=0, column=1)

        self.hide_button = tk.Button(stego_frame, text="Hide Message", command=self.hide_message)
        self.hide_button.grid(row=1, column=0, pady=5)
        self.extract_button = tk.Button(stego_frame, text="Extract Message", command=self.extract_message)
        self.extract_button.grid(row=1, column=1, pady=5)

        # Status Bar
        self.status_label = tk.Label(master, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

    def browse_input_file(self):
        filename = filedialog.askopenfilename()
        self.input_file_entry.delete(0, tk.END)
        self.input_file_entry.insert(0, filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename()
        self.output_file_entry.delete(0, tk.END)
        self.output_file_entry.insert(0, filename)

    def generate_key(self):
        try:
            self.cs.generate_key()
            self.cs.save_key(self.key_filename)
            self.status_label.config(text=f"Key saved to '{self.key_filename}'")
            messagebox.showinfo("Success", f"New key generated and saved to '{self.key_filename}'")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def load_key(self):
        if not os.path.exists(self.key_filename):
            messagebox.showerror("Error", f"Key file '{self.key_filename}' not found. Please generate a key first.")
            return False
        try:
            self.cs.load_key(self.key_filename)
            return True
        except Exception as e:
            self.status_label.config(text=f"Error loading key: {e}")
            messagebox.showerror("Error", f"Error loading key: {e}")
            return False

    def encrypt_file(self):
        if not self.load_key():
            return
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please specify both input and output files.")
            return
        try:
            self.cs.encrypt_file(input_file, output_file)
            self.status_label.config(text=f"File encrypted to '{output_file}'")
            messagebox.showinfo("Success", f"File '{input_file}' encrypted successfully to '{output_file}'")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def decrypt_file(self):
        if not self.load_key():
            return
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        if not input_file or not output_file:
            messagebox.showerror("Error", "Please specify both input and output files.")
            return
        try:
            self.cs.decrypt_file(input_file, output_file)
            self.status_label.config(text=f"File decrypted to '{output_file}'")
            messagebox.showinfo("Success", f"File '{input_file}' decrypted successfully to '{output_file}'")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def hide_message(self):
        if not self.load_key():
            return
        input_file = self.input_file_entry.get()
        output_file = self.output_file_entry.get()
        message = self.message_entry.get()
        if not input_file or not output_file or not message:
            messagebox.showerror("Error", "Please specify input file, output file, and a message.")
            return
        try:
            self.cs.hide_message(input_file, message, output_file)
            self.status_label.config(text=f"Message hidden in '{output_file}'")
            messagebox.showinfo("Success", f"Message hidden successfully in '{output_file}'")
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))

    def extract_message(self):
        if not self.load_key():
            return
        input_file = self.input_file_entry.get()
        if not input_file:
            messagebox.showerror("Error", "Please specify an input file.")
            return
        try:
            message = self.cs.extract_message(input_file)
            self.status_label.config(text="Message extracted.")
            messagebox.showinfo("Extracted Message", message)
        except Exception as e:
            self.status_label.config(text=f"Error: {e}")
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoStegoGUI(root)
    root.mainloop()
