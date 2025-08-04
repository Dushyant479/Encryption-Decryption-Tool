import tkinter as tk
from tkinter import filedialog, messagebox
from crypto_utils import encrypt_file, decrypt_file

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor")
        master.geometry("400x200")
        self.file_path = ""

        self.label = tk.Label(master, text="Choose a file to encrypt or decrypt")
        self.label.pack(pady=10)

        self.select_button = tk.Button(master, text="Browse File", command=self.browse_file)
        self.select_button.pack(pady=5) 

        self.encrypt_button = tk.Button(master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack(pady=5)

        self.decrypt_button = tk.Button(master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack(pady=5)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.label.config(text=f"Selected: {self.file_path}")

    def encrypt_file(self):
        if self.file_path:
            encrypt_file(self.file_path)
            messagebox.showinfo("Success", "File encrypted successfully")
        else:
            messagebox.showwarning("Warning", "No file selected")

    def decrypt_file(self):
        if self.file_path:
            decrypt_file(self.file_path)
            messagebox.showinfo("Success", "File decrypted successfully")
        else:
            messagebox.showwarning("Warning", "No file selected")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
