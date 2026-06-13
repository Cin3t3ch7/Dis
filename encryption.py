"""
🔐 Encryption Module for Secure Password Storage
Provides AES-256 encryption for sensitive data like IMAP passwords
"""

import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import logging

logger = logging.getLogger(__name__)

class PasswordEncryption:
    """Handles encryption and decryption of sensitive passwords"""

    def __init__(self):
        """Initialize encryption with key from environment"""
        self.encryption_key = self._get_or_generate_key()
        self.fernet = Fernet(self.encryption_key)

    def _get_or_generate_key(self) -> bytes:
        """
        Get encryption key from environment or generate a new one
        ⚠️ WARNING: Key must be consistent across restarts to decrypt existing data
        """
        env_key = os.getenv("ENCRYPTION_KEY")

        if env_key:
            try:
                # Validate key format
                key_bytes = env_key.encode('utf-8')
                # Test if it's a valid Fernet key
                Fernet(key_bytes)
                logger.info("✅ Encryption key loaded from environment")
                return key_bytes
            except Exception as e:
                raise ValueError(f"Invalid ENCRYPTION_KEY in environment: {e}")
        else:
            # Derive key from SECRET_KEY (fallback for backward compatibility)
            secret_key = os.getenv("SECRET_KEY")
            if not secret_key:
                raise ValueError("Neither ENCRYPTION_KEY nor SECRET_KEY found in environment")

            # Use PBKDF2HMAC to derive a Fernet-compatible key from SECRET_KEY
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'disney-search-pro-salt-2025',  # Static salt for consistency
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))
            logger.warning("⚠️ Using derived encryption key from SECRET_KEY. Set ENCRYPTION_KEY for better security")
            return key

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a plaintext string
        Returns: Base64-encoded encrypted string
        """
        if not plaintext:
            return ""

        try:
            encrypted_bytes = self.fernet.encrypt(plaintext.encode('utf-8'))
            return base64.urlsafe_b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            logger.error(f"❌ Encryption error: {e}")
            raise

    def decrypt(self, encrypted_text: str) -> str:
        """
        Decrypt an encrypted string
        Returns: Original plaintext string
        """
        if not encrypted_text:
            return ""

        try:
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_text.encode('utf-8'))
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            return decrypted_bytes.decode('utf-8')
        except Exception as e:
            logger.error(f"❌ Decryption error: {e}")
            raise ValueError("Failed to decrypt password. Key may have changed.")

# Global encryption instance
_encryption_instance = None

def get_encryption() -> PasswordEncryption:
    """Get or create global encryption instance"""
    global _encryption_instance
    if _encryption_instance is None:
        _encryption_instance = PasswordEncryption()
    return _encryption_instance

# Convenience functions
def encrypt_password(password: str) -> str:
    """Encrypt a password - convenience function"""
    return get_encryption().encrypt(password)

def decrypt_password(encrypted_password: str) -> str:
    """Decrypt a password - convenience function"""
    return get_encryption().decrypt(encrypted_password)
