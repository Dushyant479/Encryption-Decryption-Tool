import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from crypto_utils import encrypt_file, decrypt_file

class FileEncryptorApp:
    def __init__(self, master):
        self.master = master
        master.title("File Encryptor")
        master.geometry("430x260")
        master.resizable(False, False)
        self.file_path = ""

        frame = tk.Frame(master, padx=10, pady=10)
        frame.pack(fill='both', expand=True)

        self.label = tk.Label(frame, text="Choose a file to encrypt or decrypt", font=("Segoe UI", 11))
        self.label.pack(pady=10)

        button_frame = tk.Frame(frame)
        button_frame.pack(pady=5)

        self.select_button = tk.Button(button_frame, text="Browse File", width=13, command=self.browse_file)
        self.select_button.grid(row=0, column=0, padx=5)

        self.clear_button = tk.Button(button_frame, text="Clear", width=7, command=self.clear_file)
        self.clear_button.grid(row=0, column=1, padx=5)

        actions_frame = tk.Frame(frame)
        actions_frame.pack(pady=20)

        self.encrypt_button = tk.Button(actions_frame, text="Encrypt", width=13, command=self.encrypt_file)
        self.encrypt_button.grid(row=0, column=0, padx=10)

        self.decrypt_button = tk.Button(actions_frame, text="Decrypt", width=13, command=self.decrypt_file)
        self.decrypt_button.grid(row=0, column=1, padx=10)

    def browse_file(self):
        self.file_path = filedialog.askopenfilename()
        if self.file_path:
            self.label.config(text=f"Selected:\n{self.file_path}")

    def clear_file(self):
        self.file_path = ""
        self.label.config(text="Choose a file to encrypt or decrypt")

    def encrypt_file(self):
        if self.file_path:
            result = encrypt_file(self.master, self.file_path)
            if result:
                messagebox.showinfo("Success", "File encrypted successfully")
            else:
                messagebox.showwarning("Encryption Failed", "Encryption was cancelled or failed.")
        else:
            messagebox.showwarning("Warning", "No file selected")

    def decrypt_file(self):
        if self.file_path:
            result = decrypt_file(self.master, self.file_path)
            if result:
                messagebox.showinfo("Success", "File decrypted successfully")
            else:
                messagebox.showwarning("Decryption Failed", "Decryption was cancelled or failed.")
        else:
            messagebox.showwarning("Warning", "No file selected")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
