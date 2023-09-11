import os
import re
import json
import secrets
from getpass import getpass
from base64 import urlsafe_b64encode, urlsafe_b64decode
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from typing import Optional

LOGO = """ _____ _ _ _ ____     _____                         
|  _  | | | |    \   |     |___ ___ ___ ___ ___ ___ 
|   __| | | |  |  |  | | | | .'|   | .'| . | -_|  _|
|__|  |_____|____/   |_|_|_|__,|_|_|__,|_  |___|_|  
                                       |___|\n"""
DEFAULT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "default.conf")

class SymmetricCrypto:
    """
    Implementation of symmetric encryption with AES
    """

    def __init__(self, password: Optional[str] = None, salt_length: int = 32):
        """
        :param password: A secure encryption password, should be at least 32 characters long
        :param salt_length: The length of the salt, should be at least 16
        """

        self.password = password.encode()
        self.salt_length = salt_length

    def encrypt(self, plain_text: str) -> str:
        """
        Encrypts a text

        :param plaintext: The text to be encrypted
        """

        salt = secrets.token_bytes(self.salt_length)

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plain_text.encode()) + padder.finalize()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return urlsafe_b64encode(salt + iv + ciphertext).decode()

    def decrypt(self, cipher_text: str) -> str:
        """
        Decrypts a text

        :param ciphertext: The encrypted text
        """

        cipher_text = urlsafe_b64decode(cipher_text.encode())

        salt, iv, cipher_text = cipher_text[:self.salt_length], cipher_text[self.salt_length:self.salt_length + 16], cipher_text[self.salt_length + 16:]

        kdf_ = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf_.derive(self.password)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = decryptor.update(cipher_text) + decryptor.finalize()
        plaintext = unpadder.update(decrypted_data) + unpadder.finalize()

        return plaintext.decode()

# Get the correct password file.
if os.path.isfile(DEFAULT_PATH):
    with open(DEFAULT_PATH, "r") as file:
        password_file = file.read()
else:
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        password_file = input("Path to the password file or Enter to create a new one: ")
        if password_file == "":
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(LOGO)
                print("Path to the password file or Enter to create a new one: \n")
                password_file_name = input("What should the password file be called: ")
                if re.search(r'[^a-zA-Z]', password_file_name):
                    print("[Error] File name can contain only letters.")
                else:
                    if password_file_name == "":
                        password_file_name = "passwords"
                    break
                input("Enter: ")
            i = 0
            password_file = os.path.join(os.getcwd(), password_file_name + ("" if i == 0 else str(i)) + ".pwd")
            while os.path.isfile(password_file):
                i += 1
                password_file = os.path.join(os.getcwd(), password_file_name + ("" if i == 0 else str(i)) + ".pwd")
            break
        elif os.path.isfile(password_file):
            break
        else:
            print(f"[Error] Given file '{password_file}' not found.")
        input("\nEnter: ")

    set_default_file = input("\nDo you want to set this file as default? [Y or Enter] ")
    if set_default_file == "Y":
        with open(DEFAULT_PATH, "w") as file:
            file.write(password_file)

passwords = []

# Enter / set the master password for encrypting / decrypting the passwords.
while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    if os.path.isfile(password_file):
        master_password = getpass("Please enter the master password of the file: ")
        try:
            with open(password_file, "r") as file:
                encrypted_passwords = file.read()
        except Exception as e:
            print("[Error] Error loading the file: " + str(e))
        else:
            try:
                raw_passwords = SymmetricCrypto(master_password).decrypt(encrypted_passwords)
                passwords = json.loads(raw_passwords)
            except:
                print("[Error] The master password is incorrect or the file is corrupted.")
            else:
                break
    else:
        master_password = getpass("Please enter a secure master password: ")
        if len(master_password) < 10:
            print("[Error] Master password must consist of at least 10 characters (a good password usually has 16 characters)")
        elif not re.search(r'[A-Z]', master_password):
            print("[Error] Your password does not contain a capital letter.")
        elif not re.search(r'[a-z]', master_password):
            print("[Error] Your password does not contain a lowercase letter.")
        elif not re.search(r'[!@#$%^&*()_+{}\[\]:;<>,.?~\\]', master_password):
            print("[Error] Your password does not contain any special characters.")
        else:
            repeat_master_password = getpass("Please repeat your master password: ")
            if not repeat_master_password == master_password:
                print("[Error] The passwords do not match.")
            else:
                break
    input("\nEnter: ")

def save_passwords():
    raw_passwords = json.dumps(passwords)
    encrypted_passwords = SymmetricCrypto(master_password).encrypt(raw_passwords)
    with open(password_file, "w") as file:
        file.write(encrypted_passwords)

start_index = 0

while True:
    os.system('cls' if os.name == 'nt' else 'clear')
    print(LOGO)
    print("Passwords:")
    for index, password in enumerate(passwords[start_index:start_index+15], start = start_index + 1):
        print(f"  {index}. {password['password']}" + (" - " + password["website"] if not password["website"] is None else ""))
    if len(passwords) == 0:
        print("No passwords yet.")
    print(" ")
    option = input('Enter to view more passwords, Numbers to view passwords in detail, or "add" to add a new password: ')
    if option.lower() == "Q":
        print("Saving Passwords...")
        save_passwords()
        break
    if option == "":
        if len(passwords) > 15:
            start_index += 15
    elif option == "add":
        os.system('cls' if os.name == 'nt' else 'clear')
        print(LOGO)
        print("- New Password -")
        new_password = getpass("Enter password: ")
        if not new_password == "":
            new_username = input("(Optional) Enter username: ")
            new_username = None if new_username in ["", " "] else new_username
            new_email = input("(Optional) Enter email: ")
            new_email = None if new_email in ["", " "] else new_email
            new_website = input("(Optional) Enter website [e.g. github.com]: ")
            new_website = None if new_website in ["", " "] else new_website
            new_description = input("(Optional) Enter description: ")
            new_description = None if new_description in ["", " "] else new_description
            new_pwd_data = {"password": new_password, "username": new_username, "email": new_email, "website": new_website, "description": new_description}
            passwords = [new_pwd_data] + passwords
            save_passwords()
            print("Password saved!")
            input("Enter: ")
        start_index = 0
    else:
        try:
            int(option)
        except:
            pass
        else:
            index = int(option) - 1
            try:
                password = passwords[index]
            except:
                pass
            else:
                os.system('cls' if os.name == 'nt' else 'clear')
                print(LOGO)
                print(f"Password: {password['password']}")
                if not password['username'] is None:
                    print(f"Username: {password['username']}")
                if not password['email'] is None:
                    print(f"E-Mail: {password['email']}")
                if not password['website'] is None:
                    print(f"Website: {password['website']}")
                if not password['description'] is None:
                    print(f"Description: {password['description']}")
                option2  = input("\nDelete or Enter: ")
                if option2.lower() in ["d", "delete", "del"]:
                    passwords.pop(index)
                    save_passwords()
