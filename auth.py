import os
import hashlib
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class AuthManager:
    def __init__(self):
        self.iterations = 500000

    def generate_salt(self):
        """Generate a random 16-byte salt"""
        return os.urandom(16)

    def derive_key(self, password, salt):     
        """Derive key from password using PBKDF2"""
        key = hashlib.pbkdf2_hmac(  
            'sha256',
            password.encode(),
            salt,
            self.iterations
        )
        return key 
    
    def derive_root_key(self, password, salt):
        """Derive 32-byte root key from password"""
        return hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            self.iterations,
            dklen=32
        )
    
    def derive_subkey(self, root_key, purpose):
        """Derive subkey from root key using HKDF"""
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=purpose.encode(),
            backend=default_backend()
        )
        return hkdf.derive(root_key)

    def create_master_password(self, password):
        """Create master password hash and salt"""
        salt = self.generate_salt()
        key = self.derive_key(password, salt)

        return key.hex(), salt.hex()

    def verify_master_password(self, password, stored_hash, stored_salt):
        """Verify master password against stored hash"""
        salt = bytes.fromhex(stored_salt)
        derived_key = self.derive_key(password, salt)
