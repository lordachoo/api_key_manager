#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <sodium.h>
#include <getopt.h>

#define MAX_DESC_LEN 256
#define MAX_KEY_LEN 256
#define MASTER_KEY_LEN crypto_secretbox_KEYBYTES
#define NONCE_LEN crypto_secretbox_NONCEBYTES

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

    const char *sql = "CREATE TABLE IF NOT EXISTS api_keys ("
                      "id INTEGER PRIMARY KEY AUTOINCREMENT,"
                      "description TEXT NOT NULL,"
                      "encrypted_key BLOB NOT NULL,"
                      "key_len INTEGER NOT NULL);";
    
    rc = sqlite3_exec(db, sql, 0, 0, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        exit(1);
    }
}

void encrypt_key(const char *plain_key, size_t key_len, unsigned char *encrypted) {
    unsigned char nonce[NONCE_LEN];
    randombytes_buf(nonce, sizeof nonce);

    if (crypto_secretbox_easy(encrypted, (const unsigned char *)plain_key, key_len,
                             nonce, master_key) != 0) {
        fprintf(stderr, "Encryption failed\n");
        exit(1);
    }
}

void decrypt_key(const unsigned char *encrypted, size_t cipher_len, char *plain_key) {
    if (crypto_secretbox_open_easy((unsigned char *)plain_key, encrypted, cipher_len,
                                  encrypted + cipher_len - NONCE_LEN, master_key) != 0) {
        fprintf(stderr, "Decryption failed - invalid master key?\n");
        exit(1);
    }
}

void add_key(const char *description, const char *api_key) {
    APIKey new_key;
    strncpy(new_key.description, description, MAX_DESC_LEN);
    new_key.key_len = strlen(api_key) + 1; // Include null terminator
    
    encrypt_key(api_key, new_key.key_len, (unsigned char *)new_key.encrypted_key);

    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO api_keys (description, encrypted_key, key_len) VALUES (?, ?, ?);";
    
    int rc = sqlite3_prepare_v2(db, sql, -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "SQL error: %s\n", sqlite3_errmsg(db));
        return;
    }

    sqlite3_bind_text(stmt, 1, new_key.description, -1, SQLITE_STATIC);
    sqlite3_bind_blob(stmt, 2, new_key.encrypted_key, new_key.key_len + NONCE_LEN, SQLITE_STATIC);
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
        decrypt_key(encrypted, key_len + NONCE_LEN, plain_key);
        
        printf("API Key: %s\n", plain_key);
    } else {
        printf("No key found with ID %d\n", id);
    }

    sqlite3_finalize(stmt);
}

int main(int argc, char *argv[]) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Could not initialize libsodium\n");
        return 1;
    }

    init_database();

    // In a real application, you would securely get the master key from a file or environment variable
    // For this example, we'll prompt for it
    printf("Enter master key: ");
    if (fgets((char *)master_key, MASTER_KEY_LEN, stdin) == NULL) {
        fprintf(stderr, "Error reading master key\n");
        return 1;
    }
    // Remove newline if present
    char *newline = strchr((char *)master_key, '\n');
    if (newline) *newline = '\0';

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "a:l:g:")) != -1) {
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
            default:
                fprintf(stderr, "Usage: %s [-a description] [-l] [-g id]\n", argv[0]);
                return 1;
        }
    }

    sqlite3_close(db);
    return 0;
}
