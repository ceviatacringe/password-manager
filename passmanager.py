from cryptography.hazmat.primitives import hashes, kdf
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
import os
import json
import colored


PINK = colored.fg(175)
WHITE = colored.fg(15)
GREEN = colored.fg(0)
BACKEND = default_backend()
SALT_SIZE = 32
KEY_SIZE = 32
PASSWORD_FILE = r'D:\scripts\vscode scripts\passwords.txt'


class PasswordManager:
    def __init__(self, master_password: str, pin: str) -> None:
        self.master_password = master_password
        self.pin = pin
        self.combined_password = master_password + pin
        self.data = self.read_encrypted_data_from_file()


    @staticmethod
    def generate_unique_salt() -> bytes:
        return os.urandom(SALT_SIZE)


    def derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(
            salt=salt,
            length=KEY_SIZE,
            n=2**20,
            r=8,
            p=1,
            backend=BACKEND
        )
        return kdf.derive(self.combined_password.encode())


    def encrypt_data(self, data: str, key: bytes) -> str:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=BACKEND)
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        return urlsafe_b64encode(iv + encrypted_data).decode()


    def decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        try:
            data = urlsafe_b64decode(encrypted_data.encode())
            iv, encrypted_data = data[:16], data[16:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=BACKEND)
            decryptor = cipher.decryptor()
            return (decryptor.update(encrypted_data) + decryptor.finalize()).decode()
        except UnicodeDecodeError:
            print("Decryption failed: Invalid key. Check if the master password is correct.")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            return None


    def write_encrypted_data_to_file(self) -> None:
        with open(PASSWORD_FILE, 'w') as file:
            json.dump(self.data, file)


    @staticmethod
    def read_encrypted_data_from_file() -> dict:
        try:
            with open(PASSWORD_FILE, 'r') as file:
                file_content = file.read()
                if not file_content:
                    return {}
                return json.loads(file_content)
        except FileNotFoundError:
            print("Password file does not exist. Creating a new one.")
            with open(PASSWORD_FILE, 'w') as file:
                file.write('{}')
            return {}
        except json.JSONDecodeError:
            print("Warning: Corrupted data file. Starting with an empty password database.")
            return {}


    def add_service(self) -> None:
        service = input("Enter the service name: ")
        original_data = getpass("Enter the password for the service: ")
        salt = self.generate_unique_salt()
        key = self.derive_key(salt)
        encrypted_data = self.encrypt_data(original_data, key)
        self.data[service] = {'salt': urlsafe_b64encode(salt).decode(), 'password': encrypted_data}
        self.write_encrypted_data_to_file()
        print(f"Password for {service} encrypted and stored.")


    def get_password(self) -> None:
        service_to_retrieve = input("Enter the service name to retrieve: ")
        if service_to_retrieve in self.data:
            stored_data = self.data[service_to_retrieve]
            salt = urlsafe_b64decode(stored_data['salt'].encode())
            encrypted_password = stored_data['password']
            key = self.derive_key(salt)
            decrypted_password = self.decrypt_data(encrypted_password, key)
            print(f"Password for {service_to_retrieve}: {decrypted_password}")
        else:
            print(f"No password stored for {service_to_retrieve}")


    def list_services(self) -> None:
        if self.data:
            print("List of services stored:")
            for service in self.data:
                print(service)
        else:
            print("No services stored.")


def clear_screen():
    os.system('cls' if os.name=='nt' else 'clear')


def main():
    master_password = getpass(GREEN + "Enter your master password: " + WHITE)
    pin = getpass(GREEN + "Enter your PIN: " + WHITE)
    manager = PasswordManager(master_password, pin)
    clear_screen()
    while True:
        print(WHITE + "1. " + GREEN + "Add password\n" +
              WHITE + "2. " + GREEN + "Get password\n" +
              WHITE + "3. " + GREEN + "List services\n" +  # New option to list services
              WHITE + "4. " + GREEN + "Exit" + WHITE)
        action = input().lower()
        if action == '1':
            clear_screen()
            manager.add_service()
            input("Press enter to continue...")
            clear_screen()
        elif action == '2':
            clear_screen()
            manager.get_password()
            input("Press enter to continue...")
            clear_screen()
        elif action == '3':
            clear_screen()
            manager.list_services()
            input("Press enter to continue...")
            clear_screen()
        elif action == '4':
            break


if __name__ == "__main__":
    main()
