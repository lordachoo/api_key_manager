#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sodium.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>

#define MAX_DESC_LEN 256
#define MAX_KEY_LEN 256
#define MASTER_KEY_LEN crypto_secretbox_KEYBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES
#define SALT_LEN crypto_pwhash_SALTBYTES
#define PWD_BUF_LEN 256
#define VERSION "1.3"

typedef struct {
    int id;
    char description[MAX_DESC_LEN];
    char encrypted_key[MAX_KEY_LEN];
    size_t key_len;
} APIKey;

sqlite3 *db;
unsigned char master_key[MASTER_KEY_LEN];

void init_database() {
    int rc = sqlite3_open("api_keys.db", &db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "Cannot open database: %s\n", sqlite3_errmsg(db));
        exit(1);
    }

    const char *sql[] = {
        "CREATE TABLE IF NOT EXISTS master_key ("
        "id INTEGER PRIMARY KEY CHECK (id = 1),"
        "key_hash BLOB NOT NULL);",

        "CREATE TABLE IF NOT EXISTS api_keys ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "description TEXT NOT NULL,"
        "encrypted_key BLOB NOT NULL,"
        "key_len INTEGER NOT NULL);"
    };

    for (size_t i = 0; i < sizeof(sql) / sizeof(sql[0]); i++) {
        rc = sqlite3_exec(db, sql[i], 0, 0, 0);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
            sqlite3_close(db);
            exit(1);
        }
    }
}

size_t encrypt_key(const char *plain_key, size_t key_len, unsigned char *encrypted) {
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, sizeof nonce);

    // First store the nonce at the beginning of the encrypted buffer
    memcpy(encrypted, nonce, NONCE_LEN);
    
    // Then encrypt the data and store it after the nonce
    if (crypto_secretbox_easy(encrypted + NONCE_LEN, (const unsigned char *)plain_key, key_len,
                             nonce, master_key) != 0) {
        fprintf(stderr, "Encryption failed\n");
        exit(1);
    }

    // Return total length of encrypted data (nonce + ciphertext + MAC)
    return NONCE_LEN + key_len + crypto_secretbox_MACBYTES;
}

void decrypt_key(const unsigned char *encrypted, size_t total_len, char *plain_key) {
    if (total_len <= NONCE_LEN + crypto_secretbox_MACBYTES) {
        fprintf(stderr, "Invalid encrypted data length\n");
        exit(1);
    }

    // Extract the nonce from the beginning of the encrypted data
    const unsigned char *nonce = encrypted;
    // The actual encrypted data starts after the nonce
    const unsigned char *ciphertext = encrypted + NONCE_LEN;
    // The ciphertext length includes the MAC
    size_t ciphertext_len = total_len - NONCE_LEN;

    if (crypto_secretbox_open_easy((unsigned char *)plain_key, ciphertext, ciphertext_len,
                                  nonce, master_key) != 0) {
        fprintf(stderr, "Decryption failed - invalid master key?\n");
        exit(1);
    }
}

void add_key(const char *description, const char *api_key) {
    APIKey new_key;
    // Copy description and ensure null termination
    strncpy(new_key.description, description, MAX_DESC_LEN - 1);
    new_key.description[MAX_DESC_LEN - 1] = '\0';
    size_t plain_len = strlen(api_key) + 1; // Include null terminator
    
    // Encrypt the key and get the total length of encrypted data
    new_key.key_len = encrypt_key(api_key, plain_len, (unsigned char *)new_key.encrypted_key);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO api_keys (description, encrypted_key, key_len) VALUES (?, ?, ?);";

    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, new_key.description, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, new_key.encrypted_key, new_key.key_len, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, new_key.key_len);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
    }

    sqlite3_finalize(stmt);
    printf("API key added successfully with ID: %lld\n", sqlite3_last_insert_rowid(db));
}

void list_keys() {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, description FROM api_keys;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    printf("Stored API Keys:\n");
    printf("ID\tDescription\n");
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        printf("%d\t%s\n", sqlite3_column_int(stmt, 0), sqlite3_column_text(stmt, 1));
    }

    sqlite3_finalize(stmt);
}

void get_key(int id) {
    sqlite3_stmt *stmt;
    const char *sql = "SELECT encrypted_key, key_len FROM api_keys WHERE id = ?;";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        const void *encrypted = sqlite3_column_blob(stmt, 0);
        int key_len = sqlite3_column_int(stmt, 1);
        
        char plain_key[MAX_KEY_LEN];
        decrypt_key(encrypted, key_len, plain_key);
        
        printf("API Key: %s\n", plain_key);
    } else {
        printf("No key found with ID %d\n", id);
    }

    sqlite3_finalize(stmt);
}

void delete_key(int id) {
    // First check if the key exists
    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT description FROM api_keys WHERE id = ?;";
    
    int rc = sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        printf("No key found with ID %d\n", id);
        sqlite3_finalize(stmt);
        return;
    }

    //const unsigned char *description = sqlite3_column_text(stmt, 0);
    //sqlite3_finalize(stmt);

    // Confirm deletion
    printf("Are you sure you want to delete the API key ID: %d [y/N]: ", id);
    char confirm[4];
    if (fgets(confirm, sizeof(confirm), stdin) == NULL) {
        fprintf(stderr, "Error reading confirmation\n");
        return;
    }

    if (confirm[0] != 'y' && confirm[0] != 'Y') {
        printf("Deletion cancelled\n");
        return;
    }

    // Delete the key
    const char *delete_sql = "DELETE FROM api_keys WHERE id = ?;";
    rc = sqlite3_prepare_v2(db, delete_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_int(stmt, 1, id);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE) {
        fprintf(stderr, "Error deleting key: %s\n", sqlite3_errmsg(db));
    } else {
        printf("API key deleted successfully\n");
    }

    sqlite3_finalize(stmt);
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium\n");
        return 1;
    }

    init_database();

    // Check if master key exists
    sqlite3_stmt *stmt;
    const char *check_sql = "SELECT 1 FROM master_key WHERE id = 1;";
    int rc = sqlite3_prepare_v2(db, check_sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return 1;
    }

    rc = sqlite3_step(stmt);
    int master_key_exists = (rc == SQLITE_ROW);
    sqlite3_finalize(stmt);

    // Get the password from user without showing it
    char password[PWD_BUF_LEN];
    struct termios old_term, new_term;

    // Get the current terminal settings
    if (tcgetattr(STDIN_FILENO, &old_term) != 0) {
        fprintf(stderr, "Error getting terminal attributes\n");
        return 1;
    }

    // Create new settings with echo disabled
    new_term = old_term;
    new_term.c_lflag &= ~ECHO;

    // Set the new terminal settings
    if (tcsetattr(STDIN_FILENO, TCSANOW, &new_term) != 0) {
        fprintf(stderr, "Error setting terminal attributes\n");
        return 1;
    }

    if (!master_key_exists && argc == 1) {
        printf("No master key set. Please set a master key: ");
    } else {
        printf("Enter master key: ");
    }
    fflush(stdout);

    if (fgets(password, PWD_BUF_LEN, stdin) == NULL) {
        // Restore terminal settings before returning
        tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        fprintf(stderr, "\nError reading master key\n");
        return 1;
    }

    // Print a newline since Enter key was hidden
    printf("\n");

    // Restore the original terminal settings
    if (tcsetattr(STDIN_FILENO, TCSANOW, &old_term) != 0) {
        fprintf(stderr, "Error restoring terminal attributes\n");
        return 1;
    }

    // Remove newline if present
    char *newline = strchr(password, '\n');
    if (newline) *newline = '\0';

    // Generate a key from the password
    unsigned char salt[SALT_LEN];
    memset(salt, 0x42, SALT_LEN);  // Use a fixed salt for this example

    unsigned char key_hash[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str((char *)key_hash, password, strlen(password),
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
        fprintf(stderr, "Error hashing password\n");
        return 1;
    }

    if (!master_key_exists) {
        // Store the new master key hash
        const char *insert_sql = "INSERT INTO master_key (id, key_hash) VALUES (1, ?);";
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
            return 1;
        }

        sqlite3_bind_blob(stmt, 1, key_hash, crypto_pwhash_STRBYTES, SQLITE_STATIC);
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);

        if (rc != SQLITE_DONE) {
            fprintf(stderr, "Error storing master key\n");
            return 1;
        }

        printf("Master key set successfully\n");
        if (argc == 1) {
            return 0;
        }
    } else {
        // Verify the master key
        const char *verify_sql = "SELECT key_hash FROM master_key WHERE id = 1;";
        rc = sqlite3_prepare_v2(db, verify_sql, -1, &stmt, 0);
        if (rc != SQLITE_OK) {
            fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
            return 1;
        }

        rc = sqlite3_step(stmt);
        if (rc != SQLITE_ROW) {
            fprintf(stderr, "Error retrieving master key hash\n");
            sqlite3_finalize(stmt);
            return 1;
        }

        const unsigned char *stored_hash = sqlite3_column_blob(stmt, 0);
        if (crypto_pwhash_str_verify((const char *)stored_hash, password, strlen(password)) != 0) {
            fprintf(stderr, "Invalid master key\n");
            sqlite3_finalize(stmt);
            return 1;
        }
        sqlite3_finalize(stmt);
    }

    // Generate the encryption key from the password
    if (crypto_pwhash(master_key, sizeof(master_key),
                      password, strlen(password), salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_DEFAULT) != 0) {
        fprintf(stderr, "Error deriving key from password\n");
        return 1;
    }

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "a:lg:vd:")) != -1) {
        switch (opt) {
            case 'a': // Add key
                printf("Enter API key: ");
                char api_key[MAX_KEY_LEN];
                if (fgets(api_key, MAX_KEY_LEN, stdin) == NULL) {
                    fprintf(stderr, "Error reading API key\n");
                    return 1;
                }
                // Remove newline
                newline = strchr(api_key, '\n');
                if (newline) *newline = '\0';
                
                add_key(optarg, api_key);
                break;
            case 'l': // List keys
                list_keys();
                break;
            case 'g': // Get key by ID
                get_key(atoi(optarg));
                break;
            case 'v': // Display version
                printf("\n%s version %s\n", argv[0], VERSION);
                fprintf(stderr, "Usage: %s [-a description] [-l] [-g id] [-d id] [-v]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -a <description>  Add a new API key\n");
                fprintf(stderr, "  -l               List stored API keys\n");
                fprintf(stderr, "  -g <id>          Get API key by ID\n");
                fprintf(stderr, "  -d <id>          Delete API key by ID\n");
                fprintf(stderr, "  -v               Display version information\n");
                return 0;
            case 'd': // Delete key by ID
                delete_key(atoi(optarg));
                break;
            default:
                fprintf(stderr, "Usage: %s [-a description] [-l] [-g id] [-d id] [-v]\n", argv[0]);
                fprintf(stderr, "Options:\n");
                fprintf(stderr, "  -a <description>  Add a new API key\n");
                fprintf(stderr, "  -l               List stored API keys\n");
                fprintf(stderr, "  -g <id>          Get API key by ID\n");
                fprintf(stderr, "  -d <id>          Delete API key by ID\n");
                fprintf(stderr, "  -v               Display version information\n");
                return 1;
        }
    }

    sqlite3_close(db);
    return 0;
}
