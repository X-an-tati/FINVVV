from cryptography.fernet import Fernet
import hashlib
import os

KEY_FILE = "secret.key"

# Загружаем или создаем фиксированный ключ шифрования, чтобы не было ошибки InvalidToken при перезагрузке
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        SECRET_KEY = key_file.read()
else:
    SECRET_KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(SECRET_KEY)

cipher_suite = Fernet(SECRET_KEY)

def hash_password(password: str) -> str:
    """Хэшируем пароль через SHA-256 (надежно и без ограничений длины)"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return hash_password(plain_password) == hashed_password

def encrypt_data(data: str) -> str:
    """Шифрует данные (баланс) в защищенную строку"""
    return cipher_suite.encrypt(data.encode()).decode()

def decrypt_data(encrypted_data: str) -> str:
    """Расшифровывает данные обратно «на лету»"""
    return cipher_suite.decrypt(encrypted_data.encode()).decode()