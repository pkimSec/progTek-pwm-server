# server/crypto.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
import base64
import os
import json

class VaultCrypto:
    SALT_LENGTH = 16
    KEY_LENGTH = 32  # 256 bits
    ITERATIONS = 100_000
    
    @staticmethod
    def derive_key(master_password: str, salt: bytes = None) -> tuple[bytes, bytes]:
        """
        Derive an encryption key from the master password using PBKDF2.
        Returns (key, salt) tuple.
        """
        if salt is None:
            salt = os.urandom(VaultCrypto.SALT_LENGTH)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=VaultCrypto.KEY_LENGTH,
            salt=salt,
            iterations=VaultCrypto.ITERATIONS
        )
        
        key = kdf.derive(master_password.encode())
        return key, salt

    @staticmethod
    def encrypt_data(data: dict, key: bytes) -> dict:
        """
        Encrypt dictionary data using AES-GCM.
        Returns dict with: iv, ciphertext, and tag.
        """
        aesgcm = AESGCM(key)
        iv = os.urandom(12)  # 96-bit IV for AES-GCM
        
        # Convert data to JSON string
        data_str = json.dumps(data)
        
        # Encrypt the data
        ciphertext_and_tag = aesgcm.encrypt(
            iv,
            data_str.encode(),
            None  # No additional authenticated data
        )
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext_and_tag).decode('utf-8')
        }

    @staticmethod
    def decrypt_data(encrypted_data: dict, key: bytes) -> dict:
        """
        Decrypt data using AES-GCM.
        Returns decrypted dictionary.
        """
        try:
            aesgcm = AESGCM(key)
            
            # Decode base64 values
            iv = base64.b64decode(encrypted_data['iv'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            
            # Decrypt the data
            decrypted_data = aesgcm.decrypt(
                iv,
                ciphertext,
                None  # No additional authenticated data
            )
            
            return json.loads(decrypted_data.decode())
            
        except (InvalidTag, json.JSONDecodeError) as e:
            raise ValueError("Decryption failed - invalid key or corrupted data") from e

class UserVault:
    def __init__(self, user_id: int, master_password: str):
        """Initialize vault with user ID and master password"""
        self.user_id = user_id
        self.key, self.salt = VaultCrypto.derive_key(master_password)
        
    def encrypt_entry(self, entry_data: dict) -> dict:
        """Encrypt a password entry"""
        encrypted = VaultCrypto.encrypt_data(entry_data, self.key)
        encrypted['salt'] = base64.b64encode(self.salt).decode('utf-8')
        return encrypted
        
    @staticmethod
    def decrypt_entry(encrypted_data: dict, master_password: str) -> dict:
        """Decrypt a password entry using the master password"""
        # Decode the salt and derive the key
        salt = base64.b64decode(encrypted_data['salt'])
        key, _ = VaultCrypto.derive_key(master_password, salt)
        
        # Create dict with just the encrypted data
        encrypted_content = {
            'iv': encrypted_data['iv'],
            'ciphertext': encrypted_data['ciphertext']
        }
        
        return VaultCrypto.decrypt_data(encrypted_content, key)