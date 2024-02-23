from cryptography.hazmat.primitives import hashes, kdf
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
import os
import json

BACKEND = default_backend()
SALT_SIZE = 32
KEY_SIZE = 32
PASSWORD_FILE = r'D:\scripts\vscode scripts\passwords.txt'

def generate_unique_salt() -> bytes:
    return os.urandom(SALT_SIZE)

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
        backend=BACKEND
    )
    return kdf.derive(password.encode())

def encrypt_data(data: str, key: bytes) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=BACKEND)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
    return urlsafe_b64encode(iv + encrypted_data).decode()

def decrypt_data(encrypted_data: str, key: bytes) -> str:
    data = urlsafe_b64decode(encrypted_data.encode())
    iv, encrypted_data = data[:16], data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=BACKEND)
    decryptor = cipher.decryptor()
    return (decryptor.update(encrypted_data) + decryptor.finalize()).decode()

def write_encrypted_data_to_file(data: dict):
    with open(PASSWORD_FILE, 'w') as file:
        json.dump(data, file)

def read_encrypted_data_from_file() -> dict:
    try:
        with open(PASSWORD_FILE, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def main():
    master_password = getpass("Enter your master password: ")
    pin = getpass("Enter your PIN: ")
    combined_password = master_password + pin
    
    # Add input choice
    service = input("Enter the service name: ")
    original_data = getpass("Enter the password for the service: ")
    salt = generate_unique_salt()
    key = derive_key(combined_password, salt)
    encrypted_data = encrypt_data(original_data, key)
    
    # Add read choice
    data = read_encrypted_data_from_file()
    data[service] = {'salt': urlsafe_b64encode(salt).decode(), 'password': encrypted_data}
    write_encrypted_data_to_file(data)
    
    print(f"Password for {service} encrypted and stored.")

    # Add retreive pass choice
    service_to_retrieve = input("Enter the service name to retrieve: ")
    if service_to_retrieve in data:
        stored_data = data[service_to_retrieve]
        salt = urlsafe_b64decode(stored_data['salt'].encode())
        encrypted_password = stored_data['password']
        key = derive_key(combined_password, salt)
        decrypted_password = decrypt_data(encrypted_password, key)
        print(f"Password for {service_to_retrieve}: {decrypted_password}")
    else:
        print(f"No password stored for {service_to_retrieve}")

main()
