import sys
import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox

# Encryption key derivation
def derive_key(master_password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(master_password.encode())

# AES encryption/decryption
def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    padded_data = data + b" " * (16 - len(data) % 16)
    return iv + encryptor.update(padded_data) + encryptor.finalize()

def decrypt(data, key):
    iv = data[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]).rstrip()

# Database handling
class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 300, 200)
        
        self.layout = QVBoxLayout()
        self.label = QLabel("Enter Master Password:")
        self.layout.addWidget(self.label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Unlock")
        self.login_button.clicked.connect(self.unlock_database)
        self.layout.addWidget(self.login_button)
        
        self.setLayout(self.layout)
    
    def unlock_database(self):
        master_password = self.password_input.text()
        salt = b"1234567890123456"  # Should be stored securely
        key = derive_key(master_password, salt)
        
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS passwords (site TEXT, username TEXT, password BLOB)")
            conn.commit()
            conn.close()
            QMessageBox.information(self, "Success", "Database unlocked!")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unlock database: {str(e)}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    manager = PasswordManager()
    manager.show()
    sys.exit(app.exec())
