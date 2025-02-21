# server/models.py
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    password_hash = db.Column(db.String(256))
    role = db.Column(db.String(20), nullable=False, default='user')
    invite_code = db.Column(db.String(36), unique=True)
    is_active = db.Column(db.Boolean, default=False)
    vault_key_salt = db.Column(db.String(64))  # Salt for client-side key derivation

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @staticmethod
    def generate_invite_code():
        return str(uuid.uuid4())

class PasswordEntry(db.Model):
    """
    Model for storing encrypted password entries.
    All sensitive data is stored in encrypted_data as a JSON string.
    The server never sees the decrypted content.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)  # Contains encrypted JSON with all entry data
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, server_default=db.func.now(), onupdate=db.func.now())

    def __repr__(self):
        return f'<PasswordEntry {self.id}>'

class UserVaultMeta(db.Model):
    """Stores user-specific vault metadata"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    key_salt = db.Column(db.String(64))  # Base64 encoded salt
    created_at = db.Column(db.DateTime, server_default=db.func.now())
    updated_at = db.Column(db.DateTime, onupdate=db.func.now())
    
    # Relationship to user
    user = db.relationship('User', backref=db.backref('vault_meta', uselist=False))

class UserVault:
    def __init__(self, user_id: int, master_password: str):
        self.user_id = user_id
        # Generate initial key and salt
        self.key, self.salt = VaultCrypto.derive_key(master_password)
        
    def encrypt_entry(self, entry_data: dict) -> dict:
        """
        Encrypt a password entry.
        Returns encrypted data dict with salt and encrypted content.
        """
        encrypted = VaultCrypto.encrypt_data(entry_data, self.key)
        encrypted['salt'] = base64.b64encode(self.salt).decode('utf-8')
        return encrypted
        
    @staticmethod
    def decrypt_entry(encrypted_data: dict, master_password: str) -> dict:
        """
        Decrypt a password entry using the master password.
        """
        # Decode the salt and derive the key
        salt = base64.b64decode(encrypted_data['salt'])
        key, _ = VaultCrypto.derive_key(master_password, salt)
        
        # Create dict with just the encrypted data
        encrypted_content = {
            'iv': encrypted_data['iv'],
            'ciphertext': encrypted_data['ciphertext']
        }
        
        return VaultCrypto.decrypt_data(encrypted_content, key)