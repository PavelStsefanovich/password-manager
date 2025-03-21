#include "main.h"

#include <QApplication>
#include <QStandardPaths>
#include <QDir>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QCryptographicHash>
#include <QTemporaryDir>

#include <sqlite3.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

#include <iostream>
#include <fstream>
#include <filesystem>

// Encryption Class Implementation
std::pair<QByteArray, QByteArray> Encryption::generateKeyFromPassword(const QString& password, const QByteArray& saltInput) {
    QByteArray salt = saltInput;
    if (salt.isEmpty()) {
        salt.resize(16);
        RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
    }
    
    unsigned char key[32]; // 256 bits
    
    // Use PBKDF2 for key derivation
    PKCS5_PBKDF2_HMAC(
        password.toUtf8().constData(),
        password.toUtf8().length(),
        reinterpret_cast<const unsigned char*>(salt.constData()),
        salt.length(),
        100000, // iterations
        EVP_sha256(),
        32, // key length
        key
    );
    
    QByteArray keyArray(reinterpret_cast<char*>(key), 32);
    QByteArray encodedKey = keyArray.toBase64();
    
    return {encodedKey, salt};
}

QByteArray Encryption::encrypt(const QString& data, const QByteArray& key) {
    QByteArray decodedKey = QByteArray::fromBase64(key);
    QByteArray iv(16, 0); // 16 bytes IV (AES block size)
    RAND_bytes(reinterpret_cast<unsigned char*>(iv.data()), iv.size());
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                      reinterpret_cast<const unsigned char*>(decodedKey.constData()),
                      reinterpret_cast<const unsigned char*>(iv.constData()));
    
    QByteArray dataUtf8 = data.toUtf8();
    int cipherTextLength = dataUtf8.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc());
    QByteArray cipherText(cipherTextLength, 0);
    int len = 0;
    
    EVP_EncryptUpdate(ctx, 
                     reinterpret_cast<unsigned char*>(cipherText.data()), 
                     &len, 
                     reinterpret_cast<const unsigned char*>(dataUtf8.constData()), 
                     dataUtf8.size());
    
    int finalLen = 0;
    EVP_EncryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(cipherText.data()) + len, &finalLen);
    cipherText.resize(len + finalLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    // Prepend IV to ciphertext
    QByteArray result = iv + cipherText;
    return result.toBase64();
}

QString Encryption::decrypt(const QByteArray& data, const QByteArray& key) {
    QByteArray decodedKey = QByteArray::fromBase64(key);
    QByteArray encryptedData = QByteArray::fromBase64(data);
    
    if (encryptedData.size() < 16) {
        return QString(); // Invalid data
    }
    
    // Extract IV from first 16 bytes
    QByteArray iv = encryptedData.left(16);
    QByteArray cipherText = encryptedData.mid(16);
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, 
                      reinterpret_cast<const unsigned char*>(decodedKey.constData()),
                      reinterpret_cast<const unsigned char*>(iv.constData()));
    
    int plainTextLength = cipherText.size();
    QByteArray plainText(plainTextLength, 0);
    int len = 0;
    
    EVP_DecryptUpdate(ctx, 
                     reinterpret_cast<unsigned char*>(plainText.data()), 
                     &len, 
                     reinterpret_cast<const unsigned char*>(cipherText.constData()), 
                     cipherText.size());
    
    int finalLen = 0;
    EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(plainText.data()) + len, &finalLen);
    plainText.resize(len + finalLen);
    
    EVP_CIPHER_CTX_free(ctx);
    
    return QString::fromUtf8(plainText);
}

// Database Manager Implementation
DatabaseManager::DatabaseManager(const QString& dbPath, const QString& masterPassword) 
    : dbPath(dbPath), sqliteDb(nullptr) {
    initDatabase(masterPassword);
}

DatabaseManager::~DatabaseManager() {
    close();
}

void DatabaseManager::close() {
    if (sqliteDb) {
        sqlite3_close(static_cast<sqlite3*>(sqliteDb));
        sqliteDb = nullptr;
    }
}

void DatabaseManager::initDatabase(const QString& masterPassword) {
    bool dbExists = QFile::exists(dbPath);
    
    int rc = sqlite3_open(dbPath.toUtf8().constData(), reinterpret_cast<sqlite3**>(&sqliteDb));
    if (rc != SQLITE_OK) {
        throw std::runtime_error("Cannot open database");
    }
    
    if (!dbExists) {
        // New database - create tables and store salt and password hash
        createTables();
        salt.resize(16);
        RAND_bytes(reinterpret_cast<unsigned char*>(salt.data()), salt.size());
        
        auto [key, _] = Encryption::generateKeyFromPassword(masterPassword, salt);
        encryptionKey = key;
        
        // Create password hash
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(masterPassword.toUtf8());
        hash.addData(salt.toBase64());
        masterPasswordHash = hash.result().toHex();
        
        // Store salt and password hash
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(
            static_cast<sqlite3*>(sqliteDb),
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            -1, &stmt, nullptr
        );
        
        sqlite3_bind_text(stmt, 1, "salt", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, salt.toBase64().constData(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
        
        rc = sqlite3_prepare_v2(
            static_cast<sqlite3*>(sqliteDb),
            "INSERT INTO metadata (key, value) VALUES (?, ?)",
            -1, &stmt, nullptr
        );
        
        sqlite3_bind_text(stmt, 1, "password_hash", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, masterPasswordHash.constData(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    } else {
        // Existing database - verify password and get encryption key
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(
            static_cast<sqlite3*>(sqliteDb),
            "SELECT value FROM metadata WHERE key = ?",
            -1, &stmt, nullptr
        );
        
        sqlite3_bind_text(stmt, 1, "salt", -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* saltBase64 = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            salt = QByteArray::fromBase64(QByteArray(saltBase64));
        }
        sqlite3_finalize(stmt);
        
        rc = sqlite3_prepare_v2(
            static_cast<sqlite3*>(sqliteDb),
            "SELECT value FROM metadata WHERE key = ?",
            -1, &stmt, nullptr
        );
        
        sqlite3_bind_text(stmt, 1, "password_hash", -1, SQLITE_STATIC);
        QByteArray storedHash;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
            storedHash = QByteArray(hash);
        }
        sqlite3_finalize(stmt);
        
        // Verify password
        QCryptographicHash hash(QCryptographicHash::Sha256);
        hash.addData(masterPassword.toUtf8());
        hash.addData(salt.toBase64());
        QByteArray providedHash = hash.result().toHex();
        
        if (providedHash != storedHash) {
            close();
            throw std::runtime_error("Incorrect master password");
        }
        
        // Generate encryption key
        auto [key, _] = Encryption::generateKeyFromPassword(masterPassword, salt);
        encryptionKey = key;
    }
}

void DatabaseManager::createTables() {
    char* errorMsg = nullptr;
    int rc;
    
    // Create metadata table
    rc = sqlite3_exec(
        static_cast<sqlite3*>(sqliteDb),
        "CREATE TABLE IF NOT EXISTS metadata ("
        "key TEXT PRIMARY KEY, "
        "value TEXT NOT NULL"
        ")",
        nullptr, nullptr, &errorMsg
    );
    
    if (rc != SQLITE_OK) {
        std::string error = errorMsg;
        sqlite3_free(errorMsg);
        throw std::runtime_error("SQL error: " + error);
    }
    
    // Create secrets table
    rc = sqlite3_exec(
        static_cast<sqlite3*>(sqliteDb),
        "CREATE TABLE IF NOT EXISTS secrets ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "name TEXT NOT NULL, "
        "identity TEXT, "
        "secret TEXT NOT NULL, "
        "url TEXT, "
        "notes TEXT, "
        "created_at TEXT NOT NULL, "
        "updated_at TEXT NOT NULL"
        ")",
        nullptr, nullptr, &errorMsg
    );
    
    if (rc != SQLITE_OK) {
        std::string error = errorMsg;
        sqlite3_free(errorMsg);
        throw std::runtime_error("SQL error: " + error);
    }
}

int DatabaseManager::addSecret(const Secret& secret) {
    // Encrypt sensitive data
    QByteArray encryptedIdentity;
    if (!secret.identity.isEmpty()) {
        encryptedIdentity = Encryption::encrypt(secret.identity, encryptionKey);
    }
    
    QByteArray encryptedSecret = Encryption::encrypt(secret.secret, encryptionKey);
    
    QByteArray encryptedNotes;
    if (!secret.notes.isEmpty()) {
        encryptedNotes = Encryption::encrypt(secret.notes, encryptionKey);
    }
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(
        static_cast<sqlite3*>(sqliteDb),
        "INSERT INTO secrets (name, identity, secret, url, notes, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        -1, &stmt, nullptr
    );
    
    sqlite3_bind_text(stmt, 1, secret.name.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, encryptedIdentity.constData(), encryptedIdentity.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedSecret.constData(), encryptedSecret.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, secret.url.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, encryptedNotes.constData(), encryptedNotes.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, secret.createdAt.toString(Qt::ISODate).toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 7, secret.updatedAt.toString(Qt::ISODate).toUtf8().constData(), -1, SQLITE_TRANSIENT);
    
    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        throw std::runtime_error("Failed to add secret");
    }
    
    int id = sqlite3_last_insert_rowid(static_cast<sqlite3*>(sqliteDb));
    sqlite3_finalize(stmt);
    
    return id;
}

bool DatabaseManager::updateSecret(const Secret& secret) {
    if (secret.id == -1) {
        return false;
    }
    
    // Encrypt sensitive data
    QByteArray encryptedIdentity;
    if (!secret.identity.isEmpty()) {
        encryptedIdentity = Encryption::encrypt(secret.identity, encryptionKey);
    }
    
    QByteArray encryptedSecret = Encryption::encrypt(secret.secret, encryptionKey);
    
    QByteArray encryptedNotes;
    if (!secret.notes.isEmpty()) {
        encryptedNotes = Encryption::encrypt(secret.notes, encryptionKey);
    }
    
    QDateTime updatedAt = QDateTime::currentDateTime();
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(
        static_cast<sqlite3*>(sqliteDb),
        "UPDATE secrets SET name = ?, identity = ?, secret = ?, url = ?, notes = ?, updated_at = ? "
        "WHERE id = ?",
        -1, &stmt, nullptr
    );
    
    sqlite3_bind_text(stmt, 1, secret.name.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 2, encryptedIdentity.constData(), encryptedIdentity.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 3, encryptedSecret.constData(), encryptedSecret.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 4, secret.url.toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 5, encryptedNotes.constData(), encryptedNotes.size(), SQLITE_TRANSIENT);
    sqlite3_bind_text(stmt, 6, updatedAt.toString(Qt::ISODate).toUtf8().constData(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_int(stmt, 7, secret.id);
    
    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}

bool DatabaseManager::deleteSecret(int secretId) {
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(
        static_cast<sqlite3*>(sqliteDb),
        "DELETE FROM secrets WHERE id = ?",
        -1, &stmt, nullptr
    );
    
    sqlite3_bind_int(stmt, 1, secretId);
    
    rc = sqlite3_step(stmt);
    bool success = (rc == SQLITE_DONE);
    sqlite3_finalize(stmt);
    
    return success;
}

std::optional<Secret> DatabaseManager::getSecret(int secretId) {
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(
        static_cast<sqlite3*>(sqliteDb),
        "SELECT * FROM secrets WHERE id = ?",
        -1, &stmt, nullptr
    );
    
    sqlite3_bind_int(stmt, 1, secretId);
    
    if (sqlite3_step(stmt) != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return std::nullopt;
    }
    
    Secret secret;
    secret.id = sqlite3_column_int(stmt, 0);
    secret.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
    
    // Decrypt sensitive data
    const void* identityData = sqlite3_column_blob(stmt, 2);
    int identitySize = sqlite3_column_bytes(stmt, 2);
    if (identityData && identitySize > 0) {
        QByteArray identityBlob(static_cast<const char*>(identityData), identitySize);
        secret.identity = Encryption::decrypt(identityBlob, encryptionKey);
    }
    
    const void* secretData = sqlite3_column_blob(stmt, 3);
    int secretSize = sqlite3_column_bytes(stmt, 3);
    if (secretData && secretSize > 0) {
        QByteArray secretBlob(static_cast<const char*>(secretData), secretSize);
        secret.secret = Encryption::decrypt(secretBlob, encryptionKey);
    }
    
    secret.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
    
    const void* notesData = sqlite3_column_blob(stmt, 5);
    int notesSize = sqlite3_column_bytes(stmt, 5);
    if (notesData && notesSize > 0) {
        QByteArray notesBlob(static_cast<const char*>(notesData), notesSize);
        secret.notes = Encryption::decrypt(notesBlob, encryptionKey);
    }
    
    secret.createdAt = QDateTime::fromString(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)), Qt::ISODate);
    secret.updatedAt = QDateTime::fromString(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7)), Qt::ISODate);
    
    sqlite3_finalize(stmt);
    
    return secret;
}

std::vector<Secret> DatabaseManager::getAllSecrets() {
    std::vector<Secret> secrets;
    
    sqlite3_stmt* stmt;
    int rc = sqlite3_prepare_v2(
        static_cast<sqlite3*>(sqliteDb),
        "SELECT * FROM secrets ORDER BY name",
        -1, &stmt, nullptr
    );
    
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        Secret secret;
        secret.id = sqlite3_column_int(stmt, 0);
        secret.name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        
        // Decrypt sensitive data
        const void* identityData = sqlite3_column_blob(stmt, 2);
        int identitySize = sqlite3_column_bytes(stmt, 2);
        if (identityData && identitySize > 0) {
            QByteArray identityBlob(static_cast<const char*>(identityData), identitySize);
            secret.identity = Encryption::decrypt(identityBlob, encryptionKey);
        }
        
        const void* secretData = sqlite3_column_blob(stmt, 3);
        int secretSize = sqlite3_column_bytes(stmt, 3);
        if (secretData && secretSize > 0) {
            QByteArray secretBlob(static_cast<const char*>(secretData), secretSize);
            secret.secret = Encryption::decrypt(secretBlob, encryptionKey);
        }
        
        secret.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
        
        const void* notesData = sqlite3_column_blob(stmt, 5);
        int notesSize = sqlite3_column_bytes(stmt, 5);
        if (notesData && notesSize > 0) {
            QByteArray notesBlob(static_cast<const char*>(notesData), notesSize);
            secret.notes = Encryption::decrypt(notesBlob, encryptionKey);
        }
        
        secret.createdAt = QDateTime::fromString(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 6)), Qt::ISODate);
        secret.updatedAt = QDateTime::fromString(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 7)), Qt::ISODate);
        
        secrets.push_back(secret);
    }
    
    sqlite3_finalize(stmt);
    
    return secrets;
}

// SecretDialog Implementation
SecretDialog::SecretDialog(QWidget* parent, Secret* secretPtr, const AppConfig& config, bool readOnly)
    : QDialog(parent), config(config), readOnly(readOnly) {
    clipboard = QApplication::clipboard();
    
    if (secretPtr) {
        secret = *secretPtr;
    }
    
    setupUI();
}

void SecretDialog::setupUI() {
    setMinimumWidth(450);
    
    QFormLayout* formLayout = new QFormLayout();
    
    nameInput = new QLineEdit(secret.name);
    
    identityInput = new QLineEdit(secret.identity);
    copyIdentityBtn = new QPushButton();
    copyIdentityBtn->setToolTip("Copy to clipboard");
    copyIdentityBtn->setMaximumWidth(30);
    copyIdentityBtn->setIcon(QIcon::fromTheme("edit-copy"));
    connect(copyIdentityBtn, &QPushButton::clicked, this, [this]() {
        copyToClipboard(identityInput->text());
    });
    
    QHBoxLayout* identityLayout = new QHBoxLayout();
    identityLayout->addWidget(identityInput);
    identityLayout->addWidget(copyIdentityBtn);
    
    secretInput = new QLineEdit(secret.secret);
    secretInput->setEchoMode(QLineEdit::Password);
    showSecretBtn = new QPushButton();
    showSecretBtn->setToolTip("Show secret value");
    showSecretBtn->setMaximumWidth(30);
    QString iconPath = QString("resources/images/visible-16-%1%2").arg(config.theme).arg(config.iconExt);
    showSecretBtn->setIcon(QIcon(iconPath));
    showSecretBtn->setCheckable(true);
    connect(showSecretBtn, &QPushButton::toggled, this, &SecretDialog::toggleSecretVisibility);
    
    copySecretBtn = new QPushButton();
    copySecretBtn->setToolTip("Copy to clipboard");
    copySecretBtn->setMaximumWidth(30);
    copySecretBtn->setIcon(QIcon::fromTheme("edit-copy"));
    connect(copySecretBtn, &QPushButton::clicked, this, [this]() {
        copyToClipboard(secretInput->text());
    });
    
    QHBoxLayout* secretLayout = new QHBoxLayout();
    secretLayout->addWidget(secretInput);
    secretLayout->addWidget(showSecretBtn);
    secretLayout->addWidget(copySecretBtn);
    
    urlInput = new QLineEdit(secret.url);
    copyUrlBtn = new QPushButton();
    copyUrlBtn->setToolTip("Copy to clipboard");
    copyUrlBtn->setMaximumWidth(30);
    copyUrlBtn->setIcon(QIcon::fromTheme("edit-copy"));
    connect(copyUrlBtn, &QPushButton::clicked, this, [this]() {
        copyToClipboard(urlInput->text());
    });
    
    QHBoxLayout* urlLayout = new QHBoxLayout();
    urlLayout->addWidget(urlInput);
    urlLayout->addWidget(copyUrlBtn);
    
    notesInput = new QTextEdit();
    notesInput->