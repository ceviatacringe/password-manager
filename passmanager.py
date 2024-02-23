from cryptography.hazmat.primitives import kdf, ciphers
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import urlsafe_b64encode, urlsafe_b64decode
from getpass import getpass
import os
import json
from colored import fg


PINK = fg(175)
WHITE = fg(15)
GREEN = fg(0)
SALT_SIZE = 32
KEY_SIZE = 32
PASSWORD_FILE = 'passwords.txt'
IV_SIZE = 16  # AES block size for CFB mode


class PasswordManager:
    def __init__(self, master_password: str, pin: str) -> None:
        # Initialize with password + PIN
        # Wrong credentials will still go through, but fail to decrypt later.
        self.master_password = master_password
        self.pin = pin
        self.combined_password = f"{master_password}{pin}"
        self.data = self._read_encrypted_data_from_file()

    @staticmethod
    def _generate_unique_salt() -> bytes:
        return os.urandom(SALT_SIZE)

    def _derive_key(self, salt: bytes) -> bytes:
        # Derive a key from password + pin combo
        kdf_instance = Scrypt(
            salt=salt,
            length=KEY_SIZE,
            n=2**20,
            r=8,
            p=1
        )
        return kdf_instance.derive(self.combined_password.encode())

    def _encrypt_data(self, data: str, key: bytes) -> str:
        # Encrypt data using AES in CFB mode.
        iv = os.urandom(IV_SIZE)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()
        return urlsafe_b64encode(iv + encrypted_data).decode()

    def _decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        try:
            data = urlsafe_b64decode(encrypted_data.encode())
            iv, encrypted_data = data[:IV_SIZE], data[IV_SIZE:]
            cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
            decryptor = cipher.decryptor()
            return (decryptor.update(encrypted_data) + decryptor.finalize()).decode()
        except UnicodeDecodeError:
            print("Decryption failed: Invalid key. Check if the master password and PIN are correct.")
            return None
        except Exception as e:
            print(f"An unexpected error occurred during decryption: {e}")
            return None

    def _write_encrypted_data_to_file(self) -> None:
        with open(PASSWORD_FILE, 'w') as file:
            json.dump(self.data, file)

    @staticmethod
    def _read_encrypted_data_from_file() -> dict:
        try:
            with open(PASSWORD_FILE, 'r') as file:
                file_content = file.read()
                return json.loads(file_content) if file_content else {}
        except FileNotFoundError:
            print("Password file not found. A new one will be created.")
            return {}
        except json.JSONDecodeError:
            print("Warning: Corrupted data file. Starting with an empty password database.")
            return {}

    def add_service(self) -> None:
        # Add new service
        service = input("Enter the service name: ")
        password = getpass("Enter the password for the service: ")
        salt = self._generate_unique_salt()
        key = self._derive_key(salt)
        encrypted_data = self._encrypt_data(password, key)
        self.data[service] = {'salt': urlsafe_b64encode(salt).decode(), 'password': encrypted_data}
        self._write_encrypted_data_to_file()
        print(f"Password for {service} encrypted and stored.")

    def get_password(self) -> None:
        # Get the password for a specific service
        service = input("Enter the service name to retrieve: ")
        if service in self.data:
            stored_data = self.data[service]
            salt = urlsafe_b64decode(stored_data['salt'].encode())
            encrypted_password = stored_data['password']
            key = self._derive_key(salt)
            decrypted_password = self._decrypt_data(encrypted_password, key)
            print(f"Password for {service}: {decrypted_password}")
        else:
            print(f"No password stored for {service}")

    def list_services(self) -> None:
        # List all the services with stored passwords
        if self.data:
            print("List of stored services:")
            for service in self.data:
                print(service)
        else:
            print("No services stored.")

# Clear screen
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Main function handles user interaction
def main():
    master_password = getpass(f"{GREEN}Enter your master password: {WHITE}")
    pin = getpass(f"{GREEN}Enter your PIN: {WHITE}")
    manager = PasswordManager(master_password, pin)
    clear_screen()

    while True:
        print(f"{WHITE}1. {GREEN}Add password\n{WHITE}2. {GREEN}Get password\n{WHITE}3. {GREEN}List services\n{WHITE}4. {GREEN}Exit{WHITE}")
        action = input("Select an option: ").lower()
        if action == '1':
            clear_screen()
            manager.add_service()
        elif action == '2':
            clear_screen()
            manager.get_password()
        elif action == '3':
            clear_screen()
            manager.list_services()
        elif action == '4':
            break
        input("Press enter to continue...")
        clear_screen()

if __name__ == "__main__":
    main()

