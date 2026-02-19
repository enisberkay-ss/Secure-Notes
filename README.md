# 🔐 Secure Notes

A minimal, encrypted note-taking application.\
All notes are stored locally using strong encryption.

------------------------------------------------------------------------

## ✨ Features

-   Master password authentication\
-   AES-256-GCM encryption\
-   Add, edit, and delete notes\
-   Search notes by title\
-   Brute-force protection with exponential backoff

------------------------------------------------------------------------

## 🛠 Requirements

-   Python 3.8 or higher\
-   `cryptography` library

------------------------------------------------------------------------

## 🚀 Installation

``` bash
pip install cryptography
python main.py
```

------------------------------------------------------------------------

## 📖 Usage

1.  On first launch, create a master password.\
2.  Log in using your master password.\
3.  Add, edit, delete, or search your notes.

------------------------------------------------------------------------

## 🔒 Security Details

-   Password hashing: PBKDF2 with 500,000 iterations\
-   Encryption: AES-256-GCM\
-   Unique nonce generated for each note\
-   Failed login attempts trigger exponential delays\
    (2, 4, 8, 16 seconds, etc.)

------------------------------------------------------------------------

## 📂 Project Structure

    main.py        - GUI and application logic  
    auth.py        - Password hashing and key derivation  
    encryption.py  - AES encryption/decryption  
    database.py    - SQLite database operations  

------------------------------------------------------------------------

## ⚠ Important

If you forget your master password, your notes **cannot be recovered**.\
There is no password reset mechanism.

Make regular backups of your `secure_notes.db` file.

------------------------------------------------------------------------

## 🤖 Acknowledgments

This project was developed with assistance from AI tools\
(ChatGPT / Kimi) for:

-   GUI design and CustomTkinter integration\
-   Encryption implementation\
-   Security architecture guidance\
-   Code structure and best practices
