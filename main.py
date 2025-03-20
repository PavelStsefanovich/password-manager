import base64
import hashlib
import json
import os
import platform
import shutil
import sqlite3
import sys
import tempfile
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QIcon, QPalette
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QLabel, QLineEdit, QPushButton, QTableWidget, QTableWidgetItem,
                             QMessageBox, QDialog, QTextEdit, QHeaderView, QFormLayout,
                             QGroupBox, QDialogButtonBox, QInputDialog, QFileDialog, QStatusBar)



APP_NAME = "SimplePasswordManager"
OS_CONFIG = { # Add any platform-specific config
    "windows": {
        "icon_ext": ".ico"
    },
    "linux": {
        "icon_ext": ".png"
    },
    "macos": {
        "icon_ext": ".icns"
    }
}


@dataclass
class Secret:
    """Class for storing secret information"""
    id: Optional[int] = None
    name: str = ""
    identity: str = ""
    secret: str = ""
    url: str = ""
    notes: str = ""
    created_at: datetime = None
    updated_at: datetime = None

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()


class Encryption:
    """Class for handling encryption and decryption"""

    @staticmethod
    def generate_key_from_password(password: str, salt: bytes = None) -> tuple:
        """Generate encryption key from the master password"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key, salt

    @staticmethod
    def encrypt(data: str, key: bytes) -> bytes:
        """Encrypt data using the provided key"""
        f = Fernet(key)
        return f.encrypt(data.encode())

    @staticmethod
    def decrypt(data: bytes, key: bytes) -> str:
        """Decrypt data using the provided key"""
        f = Fernet(key)
        return f.decrypt(data).decode()


class DatabaseManager:
    """Class for handling database operations"""

    def __init__(self, db_path: str, master_password: str):
        self.db_path = db_path
        self.conn = None
        self.cursor = None
        self.encryption_key = None
        self.salt = None
        self.master_password_hash = None

        # Initialize or open the database
        self._init_database(master_password)

    def _init_database(self, master_password: str):
        """Initialize the database or open existing one"""
        db_exists = os.path.exists(self.db_path)

        self.conn = sqlite3.connect(self.db_path)
        self.cursor = self.conn.cursor()

        if not db_exists:
            # New database - create tables and store salt and password hash
            self._create_tables()
            self.salt = os.urandom(16)
            self.encryption_key, _ = Encryption.generate_key_from_password(master_password, self.salt)
            self.master_password_hash = hashlib.sha256((master_password + base64.b64encode(self.salt).decode()).encode()).hexdigest()

            # Store the salt and password hash
            self.cursor.execute("INSERT INTO metadata (key, value) VALUES (?, ?)",
                             ("salt", base64.b64encode(self.salt).decode()))
            self.cursor.execute("INSERT INTO metadata (key, value) VALUES (?, ?)",
                             ("password_hash", self.master_password_hash))
            self.conn.commit()
        else:
            # Existing database - verify password and get encryption key
            self.cursor.execute("SELECT value FROM metadata WHERE key = ?", ("salt",))
            salt_b64 = self.cursor.fetchone()[0]
            self.salt = base64.b64decode(salt_b64)

            self.cursor.execute("SELECT value FROM metadata WHERE key = ?", ("password_hash",))
            stored_hash = self.cursor.fetchone()[0]

            # Verify password
            provided_hash = hashlib.sha256((master_password + salt_b64).encode()).hexdigest()
            if provided_hash != stored_hash:
                self.conn.close()
                raise ValueError("Incorrect master password")

            # Generate encryption key
            self.encryption_key, _ = Encryption.generate_key_from_password(master_password, self.salt)

    def _create_tables(self):
        """Create database tables"""
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')

        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                identity TEXT,
                secret TEXT NOT NULL,
                url TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        self.conn.commit()

    def close(self):
        """Close the database connection"""
        if self.conn:
            self.conn.close()

    def add_secret(self, secret: Secret) -> int:
        """Add a new secret to the database"""
        # Encrypt sensitive data
        encrypted_identity = Encryption.encrypt(secret.identity, self.encryption_key) if secret.identity else b''
        encrypted_secret = Encryption.encrypt(secret.secret, self.encryption_key)
        encrypted_notes = Encryption.encrypt(secret.notes, self.encryption_key) if secret.notes else b''

        self.cursor.execute('''
            INSERT INTO secrets (name, identity, secret, url, notes, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            secret.name,
            encrypted_identity,
            encrypted_secret,
            secret.url,
            encrypted_notes,
            secret.created_at.isoformat(),
            secret.updated_at.isoformat()
        ))
        self.conn.commit()
        return self.cursor.lastrowid

    def update_secret(self, secret: Secret) -> bool:
        """Update an existing secret"""
        if not secret.id:
            return False

        # Encrypt sensitive data
        encrypted_identity = Encryption.encrypt(secret.identity, self.encryption_key) if secret.identity else b''
        encrypted_secret = Encryption.encrypt(secret.secret, self.encryption_key)
        encrypted_notes = Encryption.encrypt(secret.notes, self.encryption_key) if secret.notes else b''

        secret.updated_at = datetime.now()

        self.cursor.execute('''
            UPDATE secrets
            SET name = ?, identity = ?, secret = ?, url = ?, notes = ?, updated_at = ?
            WHERE id = ?
        ''', (
            secret.name,
            encrypted_identity,
            encrypted_secret,
            secret.url,
            encrypted_notes,
            secret.updated_at.isoformat(),
            secret.id
        ))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def delete_secret(self, secret_id: int) -> bool:
        """Delete a secret by ID"""
        self.cursor.execute("DELETE FROM secrets WHERE id = ?", (secret_id,))
        self.conn.commit()
        return self.cursor.rowcount > 0

    def get_secret(self, secret_id: int) -> Optional[Secret]:
        """Get a secret by ID"""
        self.cursor.execute("SELECT * FROM secrets WHERE id = ?", (secret_id,))
        row = self.cursor.fetchone()

        if not row:
            return None

        # Decrypt sensitive data
        identity = Encryption.decrypt(row[2], self.encryption_key) if row[2] else ""
        secret_value = Encryption.decrypt(row[3], self.encryption_key)
        notes = Encryption.decrypt(row[5], self.encryption_key) if row[5] else ""

        return Secret(
            id=row[0],
            name=row[1],
            identity=identity,
            secret=secret_value,
            url=row[4],
            notes=notes,
            created_at=datetime.fromisoformat(row[6]),
            updated_at=datetime.fromisoformat(row[7])
        )

    def get_all_secrets(self) -> List[Secret]:
        """Get all secrets"""
        self.cursor.execute("SELECT * FROM secrets ORDER BY name")
        rows = self.cursor.fetchall()

        secrets = []
        for row in rows:
            # Decrypt sensitive data
            identity = Encryption.decrypt(row[2], self.encryption_key) if row[2] else ""
            secret_value = Encryption.decrypt(row[3], self.encryption_key)
            notes = Encryption.decrypt(row[5], self.encryption_key) if row[5] else ""

            secrets.append(Secret(
                id=row[0],
                name=row[1],
                identity=identity,
                secret=secret_value,
                url=row[4],
                notes=notes,
                created_at=datetime.fromisoformat(row[6]),
                updated_at=datetime.fromisoformat(row[7])
            ))

        return secrets


class SecretDialog(QDialog):
    """Dialog for adding or editing secrets"""

    def __init__(self, parent=None, secret=None, main_config={}, read_only=False):
        super().__init__(parent)
        self.secret = secret or Secret()
        self.read_only = read_only
        self.main_config = main_config
        self.clipboard = QApplication.clipboard()
        self.setup_ui()

    def setup_ui(self):
        """Set up the dialog UI"""
        self.setMinimumWidth(450)

        form_layout = QFormLayout()

        self.name_input = QLineEdit(self.secret.name)

        self.identity_input = QLineEdit(self.secret.identity)
        self.copy_identity_btn = QPushButton()
        self.copy_identity_btn.setToolTip("Copy to clipboard")
        self.copy_identity_btn.setMaximumWidth(30)          
        self.copy_identity_btn.setIcon(QIcon.fromTheme("edit-copy"))
        self.copy_identity_btn.clicked.connect(lambda checked=False, field=self.identity_input: self.copy_to_clipboard(field.text()))

        identity_layout = QHBoxLayout()
        identity_layout.addWidget(self.identity_input)
        identity_layout.addWidget(self.copy_identity_btn)

        self.secret_input = QLineEdit(self.secret.secret)
        self.secret_input.setEchoMode(QLineEdit.Password)
        self.show_secret_btn = QPushButton()
        self.show_secret_btn.setToolTip("Show secret value")
        self.show_secret_btn.setMaximumWidth(30)          
        self.show_secret_btn.setIcon(QIcon(f'resources/images/visible-16-{self.main_config["theme"]}{self.main_config["icon_ext"]}'))
        self.show_secret_btn.setCheckable(True)
        self.show_secret_btn.toggled.connect(self.toggle_secret_visibility)
        self.copy_secret_btn = QPushButton()
        self.copy_secret_btn.setToolTip("Copy to clipboard")
        self.copy_secret_btn.setMaximumWidth(30)          
        self.copy_secret_btn.setIcon(QIcon.fromTheme("edit-copy"))
        self.copy_secret_btn.clicked.connect(lambda checked=False, field=self.secret_input: self.copy_to_clipboard(field.text()))

        secret_layout = QHBoxLayout()
        secret_layout.addWidget(self.secret_input)
        secret_layout.addWidget(self.show_secret_btn)
        secret_layout.addWidget(self.copy_secret_btn)

        self.url_input = QLineEdit(self.secret.url)
        self.copy_url_btn = QPushButton()
        self.copy_url_btn.setToolTip("Copy to clipboard")
        self.copy_url_btn.setMaximumWidth(30)          
        self.copy_url_btn.setIcon(QIcon.fromTheme("edit-copy"))
        self.copy_url_btn.clicked.connect(lambda checked=False, field=self.url_input: self.copy_to_clipboard(field.text()))

        url_layout = QHBoxLayout()
        url_layout.addWidget(self.url_input)
        url_layout.addWidget(self.copy_url_btn)        

        self.notes_input = QTextEdit()
        self.notes_input.setText(self.secret.notes)
        self.notes_input.setMinimumHeight(100)

        form_layout.addRow("Name:", self.name_input)
        form_layout.addRow("Identity:", identity_layout)
        form_layout.addRow("Secret:", secret_layout)
        form_layout.addRow("URL:", url_layout)
        form_layout.addRow("Notes:", self.notes_input)

        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)

        main_layout = QVBoxLayout()
        main_layout.addLayout(form_layout)
        main_layout.addWidget(button_box)

        if self.read_only:
            self.setWindowTitle("View Secret")
            self.name_input.setReadOnly(True)
            self.identity_input.setReadOnly(True)
            self.secret_input.setReadOnly(True)
            self.url_input.setReadOnly(True)
            self.notes_input.setReadOnly(True)
        else:
            self.setWindowTitle("Add Secret" if not self.secret.id else "Edit Secret")  

        self.status_bar = QStatusBar()
        main_layout.addStretch()
        main_layout.addWidget(self.status_bar)

        self.setLayout(main_layout)

        # Set custom tab order to prioritize text input widgets
        QWidget.setTabOrder(self.name_input, self.identity_input)
        QWidget.setTabOrder(self.identity_input, self.secret_input)
        QWidget.setTabOrder(self.secret_input, self.url_input)
        QWidget.setTabOrder(self.url_input, self.notes_input)

    def copy_to_clipboard(self, text):
        self.clipboard.setText(text)
        self.status_bar.setStyleSheet("color: green;")
        self.status_bar.showMessage(f"Copied to clipboard", 2000)

    def toggle_secret_visibility(self, checked):
        """Toggle password visibility"""
        if checked:
            self.secret_input.setEchoMode(QLineEdit.Normal)
            self.show_secret_btn.setIcon(QIcon(f'resources/images/invisible-16-{self.main_config["theme"]}{self.main_config["icon_ext"]}'))
        else:
            self.secret_input.setEchoMode(QLineEdit.Password)
            self.show_secret_btn.setIcon(QIcon(f'resources/images/visible-16-{self.main_config["theme"]}{self.main_config["icon_ext"]}'))

    def accept(self):
        """Validate and accept the dialog"""
        if not self.name_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Name is required")
            return

        if not self.secret_input.text().strip():
            QMessageBox.warning(self, "Validation Error", "Secret is required")
            return

        # Update secret object with values from form
        self.secret.name = self.name_input.text().strip()
        self.secret.identity = self.identity_input.text().strip()
        self.secret.secret = self.secret_input.text().strip()
        self.secret.url = self.url_input.text().strip()
        self.secret.notes = self.notes_input.toPlainText().strip()

        super().accept()


class LoginDialog(QDialog):
    """Dialog for entering master password"""

    def __init__(self, parent=None, main_config={}, is_new_db=False):
        super().__init__(parent)
        self.main_config = main_config
        self.password = ""
        self.db_path = ""
        self.is_new_db = is_new_db
        self.setup_ui()

    def check_db_configured(self):
        if not self.is_new_db:
            if self.main_config.get("db_path"):
                db_file_path = Path(self.main_config["db_path"])
                if db_file_path.exists():
                    self.file_path_input.setText(db_file_path.as_posix())

    def setup_ui(self):
        """Set up the dialog UI"""
        title = "Create Password Vault" if self.is_new_db else "Open Password Vault"
        self.setWindowTitle(title)
        self.setMinimumWidth(400)

        layout = QVBoxLayout()

        # File selection
        file_group = QGroupBox("Password Vault File")
        file_layout = QHBoxLayout()

        self.file_path_input = QLineEdit()
        self.file_path_input.setReadOnly(True)
        self.check_db_configured()
        self.browse_button = QPushButton("Browse")
        self.browse_button.clicked.connect(self.browse_file)

        file_layout.addWidget(self.file_path_input)
        file_layout.addWidget(self.browse_button)
        file_group.setLayout(file_layout)

        # Password fields
        password_group = QGroupBox("Master Password")
        password_layout = QVBoxLayout()

        password_form = QFormLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        password_form.addRow("Password:", self.password_input)

        if self.is_new_db:
            self.confirm_input = QLineEdit()
            self.confirm_input.setEchoMode(QLineEdit.Password)
            password_form.addRow("Confirm:", self.confirm_input)

        password_layout.addLayout(password_form)
        password_group.setLayout(password_layout)

        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.validate)
        button_box.rejected.connect(self.reject)

        # Add to main layout
        layout.addWidget(file_group)
        layout.addWidget(password_group)
        layout.addWidget(button_box)

        self.setLayout(layout)

    def browse_file(self):
        """Browse for database file"""
        if self.is_new_db:
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Create Password Vault", "", "SQLite Database (*.db);;All Files (*)"
            )
        else:
            file_path, _ = QFileDialog.getOpenFileName(
                self, "Open Password Vault", "", "SQLite Database (*.db);;All Files (*)"
            )

        if file_path:
            self.file_path_input.setText(file_path)

    def validate(self):
        """Validate inputs before accepting dialog"""
        file_path = self.file_path_input.text()
        password = self.password_input.text()

        if not file_path:
            QMessageBox.warning(self, "Validation Error", "Please select a vault file")
            return

        if not password:
            QMessageBox.warning(self, "Validation Error", "Please enter a master password")
            return

        if self.is_new_db:
            confirm = self.confirm_input.text()
            if password != confirm:
                QMessageBox.warning(self, "Validation Error", "Passwords do not match")
                return

        self.password = password
        self.db_path = file_path
        super().accept()


class SortableTableWidgetItem(QTableWidgetItem):
    """Custom QTableWidgetItem that sorts properly for different data types"""

    def __lt__(self, other):
        # Get the user role data for sorting
        my_data = self.data(Qt.UserRole)
        other_data = other.data(Qt.UserRole)

        # If we have custom sort data, use it
        if my_data is not None and other_data is not None:
            return my_data < other_data

        # Fall back to default sorting
        return super().__lt__(other)


class PasswordManagerMainWindow(QMainWindow):
    """Main window for the Password Manager application"""

    def __init__(self, main_config):
        super().__init__()
        self.db_manager = None
        self.current_search = ""
        self.main_config = main_config
        self.setup_ui()

    def showEvent(self, event):
        # This method is called whenever the window is shown
        super().showEvent(event)

        # Only show login dialog if not already logged in
        if not self.db_manager:
            # Give the main window time to display before showing the login dialog
            # Using single shot timer ensures main window is fully rendered
            QTimer.singleShot(100, self.show_login_dialog)

    def setup_ui(self):
        """Set up the main window UI"""
        self.setWindowTitle("Secure Password Manager")
        self.setMinimumSize(800, 600)

        # Main central widget and layout
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)

        # Create buttons and search bar
        button_layout = QHBoxLayout()
        self.add_button = QPushButton("Add Secret")
        self.add_button.clicked.connect(self.add_secret)
        self.edit_button = QPushButton("Edit Secret")
        self.edit_button.clicked.connect(self.edit_secret)
        self.delete_button = QPushButton("Delete Secret")
        self.delete_button.clicked.connect(self.delete_secret)
        search_label = QLabel("Search:")
        self.search_input = QLineEdit()
        self.search_input.textChanged.connect(self.search_secrets)
        button_layout.addWidget(self.add_button)
        button_layout.addWidget(self.edit_button)
        button_layout.addWidget(self.delete_button)
        button_layout.addStretch()
        button_layout.addWidget(search_label)
        button_layout.addWidget(self.search_input)

        # Create table for secrets
        self.secrets_table = QTableWidget()
        self.secrets_table.setColumnCount(4)
        self.secrets_table.setHorizontalHeaderLabels(["Name", "Identity", "URL", "Last Updated"])

        # Change from setSectionResizeMode to setResizeMode to allow manual column resizing
        self.secrets_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)

        # Set initial column widths but allow users to resize
        self.secrets_table.horizontalHeader().setStretchLastSection(True)

        self.secrets_table.setColumnWidth(0, 200)
        self.secrets_table.setColumnWidth(1, 150)
        self.secrets_table.setColumnWidth(2, 150)
        self.secrets_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.secrets_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.secrets_table.doubleClicked.connect(self.view_secret)

        # Enable sorting
        self.secrets_table.setSortingEnabled(True)

        # Add widgets to main layout
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.secrets_table)

        # Create status bar
        self.status_bar = self.statusBar()

        # Set central widget
        self.setCentralWidget(central_widget)

        # Create menu bar
        self.create_menu_bar()

    def display_current_vault(self, db_path=""):
        if hasattr(self, "current_vault_label"):
            self.status_bar.removeWidget(self.current_vault_label)
            self.current_vault_label.deleteLater()
        if db_path:
            self.current_vault_label = QLabel(f"Vault: {db_path}")
        else:
            self.current_vault_label = QLabel("<span style='color:red;'>No vault is open</span>")
        self.status_bar.addPermanentWidget(self.current_vault_label)
        self.status_bar.setStyleSheet("")

    def create_menu_bar(self):
        """Create the menu bar"""
        menu_bar = self.menuBar()

        # File menu
        file_menu = menu_bar.addMenu("File")

        new_action = QAction("New Vault", self)
        new_action.triggered.connect(self.new_database)
        file_menu.addAction(new_action)

        open_action = QAction("Open Vault", self)
        open_action.triggered.connect(self.open_database)
        file_menu.addAction(open_action)

        file_menu.addSeparator()

        change_password_action = QAction("Change Master Password", self)
        change_password_action.triggered.connect(self.change_master_password)
        file_menu.addAction(change_password_action)

        delete_action = QAction("Delete Vault", self)
        delete_action.triggered.connect(self.delete_database)
        file_menu.addAction(delete_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Help menu
        help_menu = menu_bar.addMenu("Help")

        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_login_dialog(self):
        """Show the login dialog"""
        dialog = LoginDialog(self, main_config=self.main_config)
        result = dialog.exec()

        if result == QDialog.Accepted:
            try:
                self.db_manager = DatabaseManager(dialog.db_path, dialog.password)
                self.update_main_config(merge_dict={"db_path": dialog.db_path})
                self.refresh_secrets_table()
                self.display_current_vault(dialog.db_path)
                self.status_bar.showMessage(f"Vault opened successfully", 6000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open vault: {str(e)}")
                self.show_login_dialog()
        else:
            self.display_current_vault()

    def new_database(self):
        """Create a new database"""
        dialog = LoginDialog(self, main_config=self.main_config, is_new_db=True)
        result = dialog.exec()

        if result == QDialog.Accepted:
            try:
                if self.db_manager:
                    self.db_manager.close()
                self.db_manager = DatabaseManager(dialog.db_path, dialog.password)
                self.update_main_config(merge_dict={"db_path": dialog.db_path})
                self.refresh_secrets_table()
                self.display_current_vault(dialog.db_path)
                self.status_bar.showMessage(f"New vault created successfully", 6000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to create vault: {str(e)}")

    def open_database(self):
        """Open an existing database"""
        dialog = LoginDialog(self, main_config=self.main_config)
        result = dialog.exec()

        if result == QDialog.Accepted:
            try:
                if self.db_manager:
                    self.db_manager.close()
                self.db_manager = DatabaseManager(dialog.db_path, dialog.password)
                self.update_main_config(merge_dict={"db_path": dialog.db_path})
                self.refresh_secrets_table()
                self.display_current_vault(dialog.db_path)
                self.status_bar.showMessage(f"Vault opened successfully", 6000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to open vault: {str(e)}")

    def update_main_config(self, merge_dict):
        """Shallowly merges merge_dict with main_config and saves to disk"""
        self.main_config = {**self.main_config, **merge_dict}
        with Path(self.main_config["config_path"]).open("w") as f:
            json.dump(self.main_config, f, indent=4)

    def change_master_password(self):
        """Change the master password"""
        if not self.db_manager:
            self.display_current_vault()
            self.status_bar.setStyleSheet("color: darkorange;")
            self.status_bar.showMessage(f"Please open a vault first", 6000)
            return

        # Get the new password
        new_password, ok = QInputDialog.getText(
            self, "Change Master Password", "Enter new master password:",
            QLineEdit.Password
        )

        if not ok or not new_password:
            return

        # Confirm the new password
        confirm_password, ok = QInputDialog.getText(
            self, "Change Master Password", "Confirm new master password:",
            QLineEdit.Password
        )

        if not ok or new_password != confirm_password:
            QMessageBox.warning(self, "Password Change Failed", "Passwords do not match")
            return

        try:
            # Create a new database with the new password
            db_path = self.db_manager.db_path
            temp_db_path = (Path(tempfile.gettempdir()) / (Path(db_path).name + '.tmp')).as_posix()

            # Get all secrets from current database
            all_secrets = self.db_manager.get_all_secrets()

            # Create new database with new password
            new_db = DatabaseManager(temp_db_path, new_password)

            # Add all secrets to new database
            for secret in all_secrets:
                new_db.add_secret(secret)

            # Close connections
            self.db_manager.close()
            new_db.close()

            # Replace old database with new one
            shutil.copy(temp_db_path, db_path)
            os.remove(temp_db_path)

            # Reopen the database
            self.db_manager = DatabaseManager(db_path, new_password)

            QMessageBox.information(self, "Success", "Master password changed successfully")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to change master password: {str(e)}")
            if Path(temp_db_path).exists():
                os.remove(temp_db_path)

    def delete_database(self):
        if not self.db_manager:
            self.display_current_vault()
            self.status_bar.setStyleSheet("color: darkorange;")
            self.status_bar.showMessage(f"Please open a vauflt first", 6000)
            return

        try:
            self.status_bar.setStyleSheet("color: darkorange;")
            db_path = self.db_manager.db_path

            # Confirm the new password
            confirm_delete, ok = QInputDialog.getText(
                self, "Delete vault", "Please type 'DELETE' to confirm:",
                QLineEdit.Normal
            )

            if not ok or confirm_delete != 'DELETE':
                QMessageBox.warning(self, "The vault was not deleted", "User confirmation failed")
                self.display_current_vault(db_path)
                return

            self.db_manager.close()
            self.db_manager = None
            os.remove(db_path)
            self.update_main_config({"db_path": ""})
            self.refresh_secrets_table()

            QMessageBox.information(self, "Success", "Vault deleted")
            self.display_current_vault()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to delete vault: {str(e)}")

    def refresh_secrets_table(self):
        """Refresh the secrets table"""
        if not self.db_manager:
            self.secrets_table.setSortingEnabled(False)
            self.secrets_table.clearContents()
            self.secrets_table.setRowCount(0)
            return

        # Store current sorting
        sort_column = self.secrets_table.horizontalHeader().sortIndicatorSection()
        sort_order = self.secrets_table.horizontalHeader().sortIndicatorOrder()

        # Temporarily disable sorting while updating
        self.secrets_table.setSortingEnabled(False)

        # Clear the table
        self.secrets_table.setRowCount(0)

        try:
            # Get all secrets
            secrets = self.db_manager.get_all_secrets()

            # Filter secrets based on search term
            if self.current_search:
                search_term = self.current_search.lower()
                secrets = [s for s in secrets if (
                    search_term in s.name.lower() or
                    search_term in s.identity.lower() or
                    search_term in s.url.lower()
                )]

            # Populate the table
            for i, secret in enumerate(secrets):
                self.secrets_table.insertRow(i)

                # Store the ID as hidden data in the first column
                name_item = SortableTableWidgetItem(secret.name)
                name_item.setData(Qt.UserRole, secret.name.lower())  # For sorting
                name_item.setData(Qt.UserRole + 1, secret.id)  # Store ID for reference
                self.secrets_table.setItem(i, 0, name_item)

                identity_item = SortableTableWidgetItem(secret.identity)
                identity_item.setData(Qt.UserRole, secret.identity.lower())
                self.secrets_table.setItem(i, 1, identity_item)

                app_item = SortableTableWidgetItem(secret.url)
                app_item.setData(Qt.UserRole, secret.url.lower())
                self.secrets_table.setItem(i, 2, app_item)

                date_item = SortableTableWidgetItem(secret.updated_at.strftime("%Y-%m-%d %H:%M"))
                date_item.setData(Qt.UserRole, secret.updated_at.timestamp())
                self.secrets_table.setItem(i, 3, date_item)

            # Restore sorting
            self.secrets_table.setSortingEnabled(True)
            self.secrets_table.horizontalHeader().setSortIndicator(sort_column, sort_order)

            self.status_bar.showMessage(f"Displaying {len(secrets)} secret(s)", 2000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to load secrets: {str(e)}")

    def search_secrets(self, text):
        """Search for secrets"""
        self.current_search = text
        self.refresh_secrets_table()

    def add_secret(self):
        """Add a new secret"""
        if not self.db_manager:
            return

        dialog = SecretDialog(self, main_config=self.main_config)
        result = dialog.exec()

        if result == QDialog.Accepted:
            try:
                # Add the secret to the database
                self.db_manager.add_secret(dialog.secret)
                self.refresh_secrets_table()
                self.status_bar.showMessage("Secret added successfully", 6000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to add secret: {str(e)}")

    def edit_secret(self):
        """Edit the selected secret"""
        if not self.db_manager:
            return

        selected_rows = self.secrets_table.selectedItems()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a secret to edit")
            return

        # Get the selected secret ID
        selected_row = selected_rows[0].row()
        secret_id = self.secrets_table.item(selected_row, 0).data(Qt.UserRole + 1)

        try:
            # Get the secret from the database
            secret = self.db_manager.get_secret(secret_id)
            if not secret:
                QMessageBox.warning(self, "Error", "Secret not found")
                return

            # Show the edit dialog
            dialog = SecretDialog(self, secret, main_config=self.main_config)
            result = dialog.exec()

            if result == QDialog.Accepted:
                # Update the secret in the database
                self.db_manager.update_secret(dialog.secret)
                self.refresh_secrets_table()
                self.status_bar.showMessage("Secret updated successfully", 6000)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to edit secret: {str(e)}")

    def view_secret(self):
        """View the selected secret details"""
        if not self.db_manager:
            return

        selected_rows = self.secrets_table.selectedItems()
        if not selected_rows:
            return

        # Get the selected secret ID
        selected_row = selected_rows[0].row()
        secret_id = self.secrets_table.item(selected_row, 0).data(Qt.UserRole + 1)

        try:
            # Get the secret from the database
            secret = self.db_manager.get_secret(secret_id)
            if not secret:
                QMessageBox.warning(self, "Error", "Secret not found")
                return

            # Show the secret details
            dialog = SecretDialog(self, secret, main_config=self.main_config, read_only=True)
            dialog.exec()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to view secret: {str(e)}")

    def delete_secret(self):
        """Delete the selected secret"""
        if not self.db_manager:
            return

        selected_rows = self.secrets_table.selectedItems()
        if not selected_rows:
            QMessageBox.information(self, "No Selection", "Please select a secret to delete")
            return

        # Get the selected secret ID
        selected_row = selected_rows[0].row()
        secret_id = self.secrets_table.item(selected_row, 0).data(Qt.UserRole + 1)  # Get ID from data
        secret_name = self.secrets_table.item(selected_row, 0).text()  # Now it's the first column

        # Confirm deletion
        confirm = QMessageBox.question(
            self, "Confirm Deletion",
            f"Are you sure you want to delete the secret '{secret_name}'?",
            QMessageBox.Yes | QMessageBox.No
        )

        if confirm == QMessageBox.Yes:
            try:
                # Delete the secret from the database
                self.db_manager.delete_secret(secret_id)
                self.refresh_secrets_table()
                self.status_bar.showMessage("Secret deleted successfully", 6000)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to delete secret: {str(e)}")

    def show_about(self):
        """Show the about dialog"""
        QMessageBox.about(
            self, "About Secure Password Manager",
            "Secure Password Manager\n\n"
            "A simple and secure password manager application.\n"
            "Features:\n"
            "- Encrypted database\n"
            "- Master password protection\n"
            "- Secure storage of passwords and other sensitive information\n"
            "- Search functionality\n\n"
            "Created with Python, SQLite and PySide6"
        )

    def closeEvent(self, event):
        """Close the database connection when closing the application"""
        if self.db_manager:
            self.db_manager.close()
        event.accept()


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if getattr(sys, 'frozen', False):
        # Running in a bundle
        base_path = sys._MEIPASS
    else:
        # Running in normal Python environment
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)


def load_app_config(app_name):
    system = platform.system()
    if system == "Windows":
        os_name = 'windows'
        config_dir = Path(os.getenv("LOCALAPPDATA")) / app_name  # C:\Users\Username\AppData\Roaming\YourApp
    elif system == "Linux":
        os_name = 'linux'
        config_dir = Path.home() / ".config" / app_name  # /home/username/.config/YourApp
    elif system == "Darwin":  # macOS
        os_name = 'macos'
        config_dir = Path.home() / "Library" / "Application Support" / app_name  # /Users/username/Library/Application Support/YourApp
    else:
        raise RuntimeError("Unsupported OS")

    # Create main configuration base
    config_data = {"os_name": os_name}
    config_data.update(OS_CONFIG[os_name])
    # config_data = {**config_data, **OS_CONFIG[os_name]}

    # Main configuration file path
    config_dir.mkdir(parents=True, exist_ok=True)
    config_path = config_dir / "config.json"        
    config_data.update({"config_path": config_path.as_posix()})

    # Load main configuration file if exists
    if config_path.exists():
        with config_path.open("r", encoding="utf-8") as f:
            config_data_from_file = json.load(f)
        config_data = {**config_data_from_file, **config_data}

    # Save complete base config to file
    with config_path.open("w", encoding="utf-8") as f:
        json.dump(config_data, f, indent=4)

    return config_data


def main():
    """Main function to run the application"""
    # Make sure required packages are available
    try:
        import cryptography
        from PySide6 import QtWidgets
    except ImportError as e:
        print(f"Error: Missing required package - {e}")
        print("Please install the required packages:")
        print("pip install pyside6 cryptography")
        return

    # Load (or create) app config from the OS-specific configuration location
    main_config = load_app_config(APP_NAME)

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Check the background color to determine dark mode
    palette = app.palette()
    main_config["theme"] = 'light'
    if palette.color(QPalette.Window).value() < 128:  # Value < 128 means a dark background
        main_config["theme"] = 'dark'

    # Set application icon and name
    app.setApplicationName(APP_NAME)
    app_icon = QIcon(resource_path(f'resources/images/favicon{main_config["icon_ext"]}'))
    app.setWindowIcon(app_icon)

    # Create and show the main window
    main_window = PasswordManagerMainWindow(main_config)
    main_window.show()

    # Run the application
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
