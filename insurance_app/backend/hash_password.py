"""
Run this once locally to generate a bcrypt hash for your real admin password.
Never commit the plaintext password or paste it into chat/logs.

Usage:
    pip install passlib[bcrypt]
    python3 hash_password.py
"""
import getpass
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

if __name__ == "__main__":
    password = getpass.getpass("Enter the new admin password: ")
    confirm = getpass.getpass("Confirm: ")
    if password != confirm:
        print("Passwords did not match.")
    else:
        print("\nInsert this into admin_users.password_hash:\n")
        print(pwd_context.hash(password))
