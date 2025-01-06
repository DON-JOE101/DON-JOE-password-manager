#!/bin/python3

'''
Advanced Password Manager
Author: DON-JOE

Features:
- Master password authentication
- Secure storage of passwords in an SQLite database
- Encryption using the cryptography library
- Random password generation
'''

import os
import sqlite3
import string
import random
from cryptography.fernet import Fernet
from getpass import getpass  # Secure password input in CLI

# Function to load or generate the encryption key
def load_key():
    if not os.path.exists("key.key"):
        # Generate a new key if not already present
        key = Fernet.generate_key()
        with open("key.key", "wb") as key_file:
            key_file.write(key)
    else:
        # Load existing key
        with open("key.key", "rb") as key_file:
            key = key_file.read()
    return key

# Encryption and Decryption class
class Encryptor:
    def __init__(self, key):
        self.cipher = Fernet(key)

    def encrypt(self, data):
        return self.cipher.encrypt(data.encode())

    def decrypt(self, encrypted_data):
        return self.cipher.decrypt(encrypted_data).decode()

# Database handler class
class Database:
    def __init__(self, db_name="passwords.db"):
        self.conn = sqlite3.connect(db_name)
        self.create_table()

    def create_table(self):
        query = """
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL
        )
        """
        self.conn.execute(query)
        self.conn.commit()

    def add_password(self, account, username, encrypted_password):
        query = "INSERT INTO passwords (account, username, password) VALUES (?, ?, ?)"
        self.conn.execute(query, (account, username, encrypted_password))
        self.conn.commit()

    def get_password(self, account):
        query = "SELECT username, password FROM passwords WHERE account = ?"
        cursor = self.conn.execute(query, (account,))
        return cursor.fetchone()

    def list_accounts(self):
        query = "SELECT account FROM passwords"
        cursor = self.conn.execute(query)
        return [row[0] for row in cursor.fetchall()]

# Main password manager class
class PasswordManager:
    def __init__(self, encryptor, db):
        self.encryptor = encryptor
        self.db = db
        self.authenticated = False

    def authenticate(self, master_password):
        encrypted_master = self.encryptor.encrypt(master_password)
        if not os.path.exists("master_password.txt"):
            with open("master_password.txt", "wb") as file:
                file.write(encrypted_master)
            print("Master password set successfully.")
            self.authenticated = True
        else:
            with open("master_password.txt", "rb") as file:
                stored_master = file.read()
            if self.encryptor.decrypt(stored_master) == master_password:
                print("Authentication successful.")
                self.authenticated = True
            else:
                print("Authentication failed. Exiting.")
                self.authenticated = False

    def add_password(self):
        account = input("Enter account name: ")
        username = input("Enter username: ")
        password = getpass("Enter password (or press Enter to generate one): ")
        if not password:
            password = self.generate_password()
            print(f"Generated password: {password}")
        encrypted_password = self.encryptor.encrypt(password)
        self.db.add_password(account, username, encrypted_password)
        print("Password saved successfully.")

    def retrieve_password(self):
        account = input("Enter account name: ")
        result = self.db.get_password(account)
        if result:
            username, encrypted_password = result
            password = self.encryptor.decrypt(encrypted_password)
            print(f"Account: {account}\nUsername: {username}\nPassword: {password}")
        else:
            print("Account not found.")

    def list_accounts(self):
        accounts = self.db.list_accounts()
        if accounts:
            print("Stored accounts:")
            for account in accounts:
                print(f"- {account}")
        else:
            print("No accounts found.")

    def generate_password(self, length=16):
        chars = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(chars) for _ in range(length))

# Main interface function
def main():
    print("Welcome to DON-JOE's Password Manager!")
    key = load_key()
    encryptor = Encryptor(key)
    db = Database()
    password_manager = PasswordManager(encryptor, db)

    # Authenticate user
    master_password = getpass("Enter master password: ")
    password_manager.authenticate(master_password)
    if not password_manager.authenticated:
        return

    # Main menu
    while True:
        print("\nMain Menu")
        print("1. Add Password")
        print("2. Retrieve Password")
        print("3. List Accounts")
        print("4. Exit")
        choice = input("Choose an option: ")

        if choice == "1":
            password_manager.add_password()
        elif choice == "2":
            password_manager.retrieve_password()
        elif choice == "3":
            password_manager.list_accounts()
        elif choice == "4":
            print("Goodbye from DON-JOE!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()

