# File Encryptor

A simple and user-friendly Python desktop application for encrypting and decrypting files using strong AES encryption. This project utilizes a graphical user interface built with Tkinter and secure cryptography powered by PyCryptodome.

---

## Features

- **Encrypt any file** with a password using AES-256 (CBC mode).
- **Decrypt previously encrypted files** securely.
- **Intuitive GUI** for straightforward operation—no console commands needed.
- **Does not store passwords or sensitive data**.

---

## Requirements

- Python 3.7 or higher
- [PyCryptodome](https://pypi.org/project/pycryptodome/) library

Install requirements with:


pip install pycryptodome

---

## Usage

1. **Clone or download the repository:**

git clone <your-repo-url>
cd <repo-folder>

2. **Run the app:**

python app.py

3. **Encrypt/Decrypt Operations:**
- Click **"Browse File"** to select any file.
- Click **"Encrypt"** to encrypt or **"Decrypt"** to decrypt.
- Enter your password when prompted.
- Choose where to save the output file.
- Success and error messages are displayed via popup dialogs.

---

## File Structure

| File              | Description                                        |
|-------------------|----------------------------------------------------|
| `app.py`          | Tkinter GUI for file selection and actions         |
| `crypto_utils.py` | File encryption and decryption (AES, PBKDF2, etc.) |

---

## Encryption Details

- **Cipher:** AES in CBC mode (256-bit key)
- **Key Derivation:** PBKDF2 with random salt, 100,000 iterations
- **IV:** Per-file random IV
- **Padding:** PKCS7

---

## Security Notes

- *Keep your password safe!* Losing your password means you cannot decrypt your files.
- No password or encryption data is stored by the application.
- Encrypted files save with `.enc` extension by default.

---

## Acknowledgments

- [PyCryptodome](https://www.pycryptodome.org/)
- Python [Tkinter GUI Toolkit](https://docs.python.org/3/library/tkinter.html)

---

*For questions, issues, or contributions—please open an issue or pull request on GitHub.*

