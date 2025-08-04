import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
from tkinter import simpledialog, filedialog, messagebox

BLOCK_SIZE = 16  

def pad(data):
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_file(file_path):
    password = simpledialog.askstring("Password", "Enter password for encryption:", show='*')
    if not password:
        return False

    with open(file_path, 'rb') as f:
        data = f.read()

    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data))

    original_filename = os.path.basename(file_path)
    default_enc_name = original_filename + ".enc"  

    save_path = filedialog.asksaveasfilename(
        defaultextension=".enc",
        filetypes=[("Encrypted Files", "*.enc")],
        initialfile=default_enc_name,
        title="Save Encrypted File As"
    )
    if not save_path:
        return False

    with open(save_path, 'wb') as f:
        f.write(salt + iv + ciphertext)

    return True

def decrypt_file(file_path):
    password = simpledialog.askstring("Password", "Enter password for decryption:", show='*')
    if not password:
        return False

    with open(file_path, 'rb') as f:
        file_data = f.read()

    salt = file_data[:16]
    iv = file_data[16:32]
    ciphertext = file_data[32:]

    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    try:
        plaintext = unpad(cipher.decrypt(ciphertext))
    except ValueError:
        messagebox.showerror("Error", "Incorrect password or corrupted file")
        return False

    
    save_path = filedialog.asksaveasfilename(
        defaultextension="",
        filetypes=[("All Files", "*.*")],
        title="Save Decrypted File As"
    )
    if not save_path:
        return False

    with open(save_path, 'wb') as f:
        f.write(plaintext)

    return True
