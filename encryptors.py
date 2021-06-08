import hashlib
import secrets
from string import ascii_letters, digits, punctuation


def key_encrypt_sha256(key):
    crypt = hashlib.sha256()
    crypt.update(key.encode())
    return int.from_bytes(crypt.hexdigest().encode(), "big")


def generate_password(length=20):
    return "".join(secrets.choice(ascii_letters + digits + punctuation) for _ in range(length))


def site_user_and_password_encrypt(site, user, password, encrypted_key):
    return (
        str(int.from_bytes(site.encode(), "big") ^ encrypted_key),
        str(int.from_bytes(user.encode(), "big") ^ encrypted_key),
        str(int.from_bytes(password.encode(), "big") ^ encrypted_key),
    )


def field_encrypt(field, encrypted_key):
    return str(int.from_bytes(field.encode(), "big") ^ encrypted_key)


def site_user_and_password_decrypt(database_row, encrypted_key):
    encrypted_site, encripted_user, encrypted_password = database_row
    decrypted_site = int(encrypted_site) ^ encrypted_key
    decrypted_user = int(encripted_user) ^ encrypted_key
    decrypted_pass = int(encrypted_password) ^ encrypted_key
    return (
        decrypted_site.to_bytes((decrypted_site.bit_length() + 7) // 8, "big").decode(),
        decrypted_user.to_bytes((decrypted_user.bit_length() + 7) // 8, "big").decode(),
        decrypted_pass.to_bytes((decrypted_pass.bit_length() + 7) // 8, "big").decode(),
    )


def field_decrypt(field, encrypted_key):
    decrypted_field = int(field) ^ encrypted_key
    return decrypted_field.to_bytes((decrypted_field.bit_length() + 7) // 8, "big").decode()
