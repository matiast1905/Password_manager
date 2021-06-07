import hashlib
import secrets
from string import ascii_letters, digits, punctuation


def key_encrypt_sha256(key):
    crypt = hashlib.sha256()
    crypt.update(key.encode())
    return int.from_bytes(crypt.hexdigest().encode(), "big")


def generate_password(length=20):
    return "".join(secrets.choice(ascii_letters + digits + punctuation) for _ in range(length))


def password_encrypt(password, encrypted_key):
    return int.from_bytes(password.encode(), "big") ^ int(encrypted_key)


def password_decrypt(encrypted_password, encrypted_key):
    decrypted_pass = encrypted_password ^ encrypted_key
    return decrypted_pass.to_bytes((decrypted_pass.bit_length() + 7) // 8, "big").decode()
