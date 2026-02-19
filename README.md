

# Secure Notes

A simple encrypted note-taking application. Notes are stored locally with AES-256 encryption.

## Features

- Master password login
- AES-256-GCM encryption
- Add, edit, delete notes
- Search by title
- Brute-force protection (exponential backoff on failed attempts)

## Requirements

- Python 3.8+
- cryptography library

## Installation

```bash
pip install cryptography
python main.py


