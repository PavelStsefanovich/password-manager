import sys
import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PySide6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QListWidget, QInputDialog

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

# Secret class
class Secret:
    def __init__(self, name, identity, secret, application, notes):
        self.name = name
        self.identity = identity
        self.secret = secret
        self.application = application
        self.notes = notes

# Database handling
class PasswordManager(QWidget):
    def __init__(self):
        super().__init__()
        self.master_key = None
        self.init_ui()
    
    def init_ui(self):
        self.setWindowTitle("Password Manager")
        self.setGeometry(100, 100, 400, 300)
        
        self.layout = QVBoxLayout()
        self.label = QLabel("Enter Master Password:")
        self.layout.addWidget(self.label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.layout.addWidget(self.password_input)
        
        self.login_button = QPushButton("Unlock")
        self.login_button.clicked.connect(self.unlock_database)
        self.layout.addWidget(self.login_button)
        
        self.secret_list = QListWidget()
        self.secret_list.hide()
        self.layout.addWidget(self.secret_list)
        
        self.add_button = QPushButton("Add Secret")
        self.add_button.clicked.connect(self.add_secret)
        self.add_button.hide()
        self.layout.addWidget(self.add_button)
        
        self.delete_button = QPushButton("Delete Secret")
        self.delete_button.clicked.connect(self.delete_secret)
        self.delete_button.hide()
        self.layout.addWidget(self.delete_button)
        
        self.setLayout(self.layout)
    
    def unlock_database(self):
        master_password = self.password_input.text()
        salt = b"1234567890123456"  # Should be stored securely
        self.master_key = derive_key(master_password, salt)
        
        try:
            conn = sqlite3.connect("passwords.db")
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS secrets (
                    name TEXT, 
                    identity TEXT, 
                    secret BLOB, 
                    application TEXT, 
                    notes TEXT
                )
            """)
            conn.commit()
            conn.close()
            self.label.setText("Database unlocked!")
            self.password_input.hide()
            self.login_button.hide()
            self.secret_list.show()
            self.add_button.show()
            self.delete_button.show()
            self.load_secrets()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to unlock database: {str(e)}")
    
    def load_secrets(self):
        self.secret_list.clear()
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM secrets")
        secrets = cursor.fetchall()
        conn.close()
        for secret in secrets:
            self.secret_list.addItem(secret[0])
    
    def add_secret(self):
        name, ok = QInputDialog.getText(self, "Add Secret", "Enter secret name:")
        if not ok or not name:
            return
        
        identity, ok = QInputDialog.getText(self, "Add Secret", "Enter identity:")
        if not ok:
            return
        
        secret, ok = QInputDialog.getText(self, "Add Secret", "Enter secret:")
        if not ok:
            return
        
        application, ok = QInputDialog.getText(self, "Add Secret", "Enter application:")
        if not ok:
            return
        
        notes, ok = QInputDialog.getText(self, "Add Secret", "Enter notes:")
        if not ok:
            return
        
        encrypted_secret = encrypt(secret.encode(), self.master_key)
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO secrets VALUES (?, ?, ?, ?, ?)", (name, identity, encrypted_secret, application, notes))
        conn.commit()
        conn.close()
        self.load_secrets()
    
    def delete_secret(self):
        selected_item = self.secret_list.currentItem()
        if not selected_item:
            return
        
        name = selected_item.text()
        conn = sqlite3.connect("passwords.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM secrets WHERE name = ?", (name,))
        conn.commit()
        conn.close()
        self.load_secrets()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    manager = PasswordManager()
    manager.show()
    sys.exit(app.exec())
