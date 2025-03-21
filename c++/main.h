#ifndef MAIN_H
#define MAIN_H

#include <QApplication>
#include <QMainWindow>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>
#include <QMessageBox>
#include <QDialog>
#include <QTextEdit>
#include <QHeaderView>
#include <QFormLayout>
#include <QGroupBox>
#include <QDialogButtonBox>
#include <QInputDialog>
#include <QFileDialog>
#include <QStatusBar>
#include <QMenuBar>
#include <QAction>
#include <QTimer>
#include <QIcon>
#include <QPalette>
#include <QClipboard>
#include <QDateTime>
#include <QTableWidgetItem>

#include <string>
#include <vector>
#include <memory>
#include <filesystem>
#include <fstream>
#include <optional>

// Forward declarations
class DatabaseManager;
class Secret;

// Constants
const QString APP_NAME = "SimplePasswordManager";

// OS-specific configuration structure
struct OSConfig {
    QString iconExt;
};

// Application configuration
struct AppConfig {
    QString osName;
    QString iconExt;
    QString configPath;
    QString dbPath;
    QString theme;
};

// Secret data structure
class Secret {
public:
    Secret() : id(-1), createdAt(QDateTime::currentDateTime()), updatedAt(QDateTime::currentDateTime()) {}
    
    int id;
    QString name;
    QString identity;
    QString secret;
    QString url;
    QString notes;
    QDateTime createdAt;
    QDateTime updatedAt;
};

// Custom QTableWidgetItem for proper sorting
class SortableTableWidgetItem : public QTableWidgetItem {
public:
    SortableTableWidgetItem(const QString& text) : QTableWidgetItem(text) {}
    
    bool operator<(const QTableWidgetItem& other) const override {
        // Get user role data for sorting
        QVariant myData = data(Qt::UserRole);
        QVariant otherData = other.data(Qt::UserRole);
        
        // If we have custom sort data, use it
        if (myData.isValid() && otherData.isValid()) {
            return myData < otherData;
        }
        
        // Fall back to default sorting
        return QTableWidgetItem::operator<(other);
    }
};

// Encryption class
class Encryption {
public:
    static std::pair<QByteArray, QByteArray> generateKeyFromPassword(const QString& password, const QByteArray& salt = QByteArray());
    static QByteArray encrypt(const QString& data, const QByteArray& key);
    static QString decrypt(const QByteArray& data, const QByteArray& key);
};

// Database Manager class
class DatabaseManager {
public:
    DatabaseManager(const QString& dbPath, const QString& masterPassword);
    ~DatabaseManager();
    
    int addSecret(const Secret& secret);
    bool updateSecret(const Secret& secret);
    bool deleteSecret(int secretId);
    std::optional<Secret> getSecret(int secretId);
    std::vector<Secret> getAllSecrets();
    
private:
    void initDatabase(const QString& masterPassword);
    void createTables();
    void close();
    
    QString dbPath;
    void* sqliteDb; // SQLite database handle, opaque pointer
    QByteArray encryptionKey;
    QByteArray salt;
    QString masterPasswordHash;
};

// Secret Dialog class
class SecretDialog : public QDialog {
    Q_OBJECT
    
public:
    SecretDialog(QWidget* parent = nullptr, Secret* secret = nullptr, const AppConfig& config = {}, bool readOnly = false);
    Secret getSecret() const { return secret; }
    
private slots:
    void toggleSecretVisibility(bool checked);
    void copyToClipboard(const QString& text);
    
private:
    void setupUI();
    void accept() override;
    
    Secret secret;
    bool readOnly;
    AppConfig config;
    QClipboard* clipboard;
    
    QLineEdit* nameInput;
    QLineEdit* identityInput;
    QPushButton* copyIdentityBtn;
    QLineEdit* secretInput;
    QPushButton* showSecretBtn;
    QPushButton* copySecretBtn;
    QLineEdit* urlInput;
    QPushButton* copyUrlBtn;
    QTextEdit* notesInput;
    QStatusBar* statusBar;
};

// Login Dialog class
class LoginDialog : public QDialog {
    Q_OBJECT
    
public:
    LoginDialog(QWidget* parent = nullptr, const AppConfig& config = {}, bool isNewDb = false);
    
    QString getPassword() const { return password; }
    QString getDbPath() const { return dbPath; }
    
private slots:
    void browseFile();
    void validate();
    
private:
    void setupUI();
    void checkDbConfigured();
    
    AppConfig config;
    QString password;
    QString dbPath;
    bool isNewDb;
    
    QLineEdit* filePathInput;
    QLineEdit* passwordInput;
    QLineEdit* confirmInput; // Only for new database
};

// Main window class
class PasswordManagerMainWindow : public QMainWindow {
    Q_OBJECT
    
public:
    PasswordManagerMainWindow(const AppConfig& config);
    ~PasswordManagerMainWindow();
    
protected:
    void showEvent(QShowEvent* event) override;
    void closeEvent(QCloseEvent* event) override;
    
private slots:
    void showLoginDialog();
    void newDatabase();
    void openDatabase();
    void changeMasterPassword();
    void deleteDatabase();
    void refreshSecretsTable();
    void searchSecrets(const QString& text);
    void addSecret();
    void editSecret();
    void viewSecret();
    void deleteSecret();
    void showAbout();
    
private:
    void setupUI();
    void createMenuBar();
    void displayCurrentVault(const QString& dbPath = "");
    void updateMainConfig(const std::map<QString, QString>& mergeDict);
    
    std::unique_ptr<DatabaseManager> dbManager;
    QString currentSearch;
    AppConfig config;
    
    QPushButton* addButton;
    QPushButton* editButton;
    QPushButton* deleteButton;
    QLineEdit* searchInput;
    QTableWidget* secretsTable;
    QStatusBar* statusBar;
    QLabel* currentVaultLabel;
};

// Helper functions
AppConfig loadAppConfig(const QString& appName);
QString resourcePath(const QString& relativePath);

#endif // MAIN_H
