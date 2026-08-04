import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoEngine:
    @staticmethod
    def generate_key() -> str:
        """Generates a secure, random base64 symmetric key."""
        return Fernet.generate_key().decode('utf-8')

    @staticmethod
    def derive_key_from_passphrase(passphrase: str, salt: bytes = None) -> tuple[str, bytes]:
        """
        Derives a valid Fernet key from a user passphrase using PBKDF2HMAC.
        Returns a tuple of (base64_key_string, salt_bytes).
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode('utf-8')))
        return key.decode('utf-8'), salt

    @staticmethod
    def encrypt_file(file_path: str, secret_key: str, output_path: str = None) -> str:
        """Encrypts a file and writes output to disk."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Input file not found: {file_path}")

        fernet = Fernet(secret_key.encode('utf-8'))
        
        with open(file_path, "rb") as f:
            data = f.read()
            
        encrypted_data = fernet.encrypt(data)
        
        if not output_path:
            output_path = file_path + ".enc"
            
        with open(output_path, "wb") as f:
            f.write(encrypted_data)
            
        return output_path

    @staticmethod
    def decrypt_file(file_path: str, secret_key: str, output_path: str = None) -> str:
        """Decrypts an encrypted file and restores original content."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Encrypted file not found: {file_path}")

        fernet = Fernet(secret_key.encode('utf-8'))
        
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
            
        decrypted_data = fernet.decrypt(encrypted_data)
        
        if not output_path:
            if file_path.endswith(".enc"):
                output_path = file_path[:-4]
            else:
                output_path = file_path + ".decrypted"
                
        with open(output_path, "wb") as f:
            f.write(decrypted_data)
            
        return output_path