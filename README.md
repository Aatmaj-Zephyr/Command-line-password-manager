## Python Command-line Password Manager

This script provides a command-line interface for managing passwords. It allows users to generate random passwords, store passwords securely in an encrypted database, and find passwords for specific applications.

### Dependencies

- `argparse`: For parsing command-line arguments.
- `base64`: For base64 encoding.
- `hashlib`: For generating SHA-256 hash of the master key.
- `random`: For generating random characters.
- `string`: For accessing string constants.
- `pyperclip`: For copying passwords to the clipboard.
- `json`: For reading and writing JSON files.
- `cryptography.fernet.Fernet`: For encryption and decryption.

### Usage

The script supports the following command-line arguments:

- `-n, --new`: Generate a new random password and store it for an application.
- `-s, --store`: Store a password for an application.
- `-f, --find`: Find a password for a specific application.

### Workflow

1. **Generate a New Password**: Use the `-n` or `--new` flag to generate a new random password. You will be prompted to enter the application name and your username. The generated password will be copied to your clipboard. You can choose to store this password or generate a new one.

2. **Store a Password**: Use the `-s` or `--store` flag to store a password for an application. You will be prompted to enter the application name, your username, and the password. The password will be stored securely in an encrypted database.

3. **Find a Password**: Use the `-f` or `--find` flag to find a password for a specific application. You will be prompted to enter the application name. If the application is found in the database, the username and password will be displayed and copied to your clipboard.

### Encryption

Passwords are encrypted using a master key provided by the user. The master key is converted to bytes and hashed using SHA-256. The hashed key is then used to generate a Fernet key, which is used for encryption and decryption.

### Database

Passwords are stored in a JSON file (`passwords.json`) located at `/IS_IA1/passwords.json`. Each entry in the JSON file contains the encrypted application name, username, and password.

### Example

To generate a new password and store it:

```
python password_manager.py -n
```

To store a password for an application:

```
python password_manager.py -s
```

To find a password for an application:

```
python password_manager.py -f
```

**Note:** Replace `password_manager.py` with the actual filename of your script.

### Security Considerations

- **Master Key**: The master key is a password to protect your passwords. Keep your master key secure and do not share it with anyone and dont forget it! It will be best if you use the password of your laptop as the master key.
- **Password Storage**: Passwords are stored in an encrypted database.
- **Clipboard**: Be cautious when using the clipboard to copy passwords, as clipboard contents can be accessed by other applications.

---

