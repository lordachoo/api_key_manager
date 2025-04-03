# API Key Manager

A secure command-line tool for storing and managing API keys using SQLite and libsodium encryption.

## Features

- Secure storage of API keys using strong encryption (libsodium)
- Master password protection with secure password hashing
   - Master password is input on the first db initialization and CANNOT be recovered if lost afterwards
- SQLite database backend for reliable storage
- Command-line interface for easy integration into scripts


## Security Features

- Uses libsodium's `crypto_secretbox_easy` for encrypting API keys
- Implements proper key derivation using `crypto_pwhash`
- Stores only hashed master password using Argon2 (via libsodium's `crypto_pwhash_str`)
- Includes MAC (Message Authentication Code) for tamper detection
- Uses unique nonces for each encryption operation

## Dependencies

- SQLite3 (`libsqlite3-dev`)
- libsodium (`libsodium-dev`)

## Building

```bash
make
```

## Usage

### First Run - Setting Master Password

On first run with no arguments, you'll be prompted to set a master password:

```bash
./api_key_manager
```

### Adding an API Key

To add a new API key:

```bash
./api_key_manager -a "Description of the key"
```

You'll be prompted for:
1. Master password
2. The API key to store

### Listing Stored Keys

To list all stored API keys (shows IDs and descriptions only, not the actual keys):

```bash
./api_key_manager -l
```

### Retrieving an API Key

To retrieve a specific API key by its ID:

```bash
./api_key_manager -g <id>
```

### Deleting an API Key

To delete a specific API key by its ID:

```bash
./api_key_manager -d <id>
```

You'll be prompted for:
1. Master password
2. Confirmation to delete the key

### Version Information

To display version information:

```bash
./api_key_manager -v
```

## Technical Details

### Database Structure

The application uses two SQLite tables:

1. `master_key`:
   - Stores the hashed master password
   - Uses Argon2 for password hashing

2. `api_keys`:
   - `id`: Unique identifier for each key
   - `description`: User-provided description
   - `encrypted_key`: The encrypted API key
   - `key_len`: Length of the encrypted data

### Encryption Process

1. **Key Derivation**:
   - Master password is processed using `crypto_pwhash` to derive the encryption key
   - Uses Argon2 with interactive parameters for good security/performance balance

2. **API Key Encryption**:
   - Each API key is encrypted using `crypto_secretbox_easy`
   - A unique random nonce is generated for each encryption
   - The nonce is stored alongside the encrypted data
   - Format: `[nonce][encrypted_data][MAC]`

3. **Storage**:
   - The complete encrypted package (nonce + encrypted data + MAC) is stored in the database
   - The total length is stored to ensure proper decryption

### Security Considerations

- The database file (`api_keys.db`) contains encrypted data but should still be protected
- The master password is never stored in plain text
- Each API key is encrypted with a unique nonce
- MAC verification ensures encrypted data hasn't been tampered with