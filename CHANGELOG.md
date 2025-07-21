# v0

- Initial Code

# v1.1

- Added Versions
- Added `-v` arg
- Added `-d <id>` arg
- Removed `api_keys.db` from being removed for `make clean`

# v1.2

- Removed echo when typing in master password for authentication.

# v1.3

Fix strncpy string truncation warning by ensuring null termination

- Modified strncpy call in add_key() to use MAX_DESC_LEN - 1 to leave room for null terminator
- Added explicit null termination after strncpy to guarantee string safety
- Resolves compiler warning about '__builtin_strncpy specified bound equals destination size'
- Prevents potential buffer overflows when handling descriptions at or near MAX_DESC_LEN
- Added Argon2 cracking info to tools/ for educational purposes
