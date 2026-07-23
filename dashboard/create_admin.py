"""
One-off CLI to create (or reset the password of) a dashboard login.
Run on the same host, after schema.sql has been applied:

    python3 create_admin.py

Reads PGHOST / PGPORT / PGUSER / PGPASSWORD / PGDATABASE from the environment,
same as the rest of the stack (psycopg2 picks these up automatically).
"""
import getpass
import sys

import psycopg2
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def main():
    username = input("Username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("Passwords do not match.")
        sys.exit(1)
    if len(password) < 8:
        print("Use at least 8 characters.")
        sys.exit(1)

    password_hash = pwd_context.hash(password)

    conn = psycopg2.connect()  # uses PG* env vars
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO dashboard_users (username, password_hash)
        VALUES (%s, %s)
        ON CONFLICT (username)
        DO UPDATE SET password_hash = EXCLUDED.password_hash, is_active = TRUE
        """,
        (username, password_hash),
    )
    conn.commit()
    cur.close()
    conn.close()
    print(f"User '{username}' created/updated.")


if __name__ == "__main__":
    main()
