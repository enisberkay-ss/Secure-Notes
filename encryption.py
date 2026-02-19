from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
import hashlib

class EncryptionManager:
    def __init__(self, encryption_key):
        self.key = encryption_key

    def derive_encryption_key(self, password):
        """Derive encryption key from password (not used in current implementation)"""
        salt = b"secure_notes_static_salt"

        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            500000,
            dklen=32
        )
        return key

    def encrypt(self, plaintext):
        """Encrypt plaintext using AES-GCM"""
        aesgcm = AESGCM(self.key)
        nonce = os.urandom(12)

        ciphertext = aesgcm.encrypt(
            nonce,
            plaintext.encode(),
            None
        )
        return ciphertext, nonce

    def decrypt(self, ciphertext, nonce):
        """Decrypt ciphertext using AES-GCM"""
        aesgcm = AESGCM(self.key)

        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            None
        )
        return plaintext.decode()