import os
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime

class CryptoManager:
    def __init__(self):
        # Generate a secure key and IV
        self.key = os.urandom(32)  # 256-bit key for AES-256
        self.iv = os.urandom(16)   # 128-bit IV for AES-CBC

    def encrypt(self, data: str) -> bytes:
        """Encrypt data using AES-256-CBC"""
        try:
            # Convert string to bytes
            data_bytes = data.encode('utf-8')
            
            # Pad the data
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(data_bytes) + padder.finalize()
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(self.iv),
                backend=default_backend()
            )
            
            # Encrypt
            encryptor = cipher.encryptor()
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            return self.iv + encrypted_data
            
        except Exception as e:
            print(f"Encryption error: {str(e)}")
            raise

    def decrypt(self, encrypted_data: bytes) -> str:
        """Decrypt data using AES-256-CBC"""
        try:
            # Extract IV and encrypted data
            iv = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            
            # Decrypt
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Unpad
            unpadder = padding.PKCS7(128).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return data.decode('utf-8')
            
        except Exception as e:
            print(f"Decryption error: {str(e)}")
            raise

    def encrypt_file(self, file_path: str, data: str):
        """Encrypt and save data to file"""
        try:
            encrypted_data = self.encrypt(data)
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
        except Exception as e:
            print(f"File encryption error: {str(e)}")
            raise

    def decrypt_file(self, file_path: str) -> str:
        """Read and decrypt data from file"""
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            return self.decrypt(encrypted_data)
        except Exception as e:
            print(f"File decryption error: {str(e)}")
            raise

    def secure_log(self, message: str, log_file: str):
        """Log message with timestamp securely"""
        try:
            timestamp = datetime.now().isoformat()
            log_entry = f"[{timestamp}] {message}"
            self.encrypt_file(log_file, log_entry)
        except Exception as e:
            print(f"Secure logging error: {str(e)}")
            raise

    def read_secure_log(self, log_file: str) -> str:
        """Read and decrypt log entries"""
        try:
            return self.decrypt_file(log_file)
        except Exception as e:
            print(f"Secure log reading error: {str(e)}")
            raise

    def secure_config(self, config_data: dict, config_file: str):
        """Encrypt and save configuration data"""
        try:
            config_json = json.dumps(config_data)
            self.encrypt_file(config_file, config_json)
        except Exception as e:
            print(f"Config encryption error: {str(e)}")
            raise

    def read_secure_config(self, config_file: str) -> dict:
        """Read and decrypt configuration data"""
        try:
            config_json = self.decrypt_file(config_file)
            return json.loads(config_json)
        except Exception as e:
            print(f"Config decryption error: {str(e)}")
            raise 