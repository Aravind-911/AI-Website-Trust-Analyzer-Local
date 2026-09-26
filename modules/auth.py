import os
import sqlite3
import hashlib
import secrets
from datetime import datetime

DATABASE_PATH = "data/trustlens.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    os.makedirs("data", exist_ok=True)

    return sqlite3.connect(DATABASE_PATH)


# =========================================================
# CREATE USER TABLE
# =========================================================

def initialize_database():
    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
        """
    )

    connection.commit()
    connection.close()


# =========================================================
# PASSWORD HASHING
# =========================================================

def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        200000
    ).hex()

    return password_hash, salt


# =========================================================
# REGISTER USER
# =========================================================

def register_user(name, email, password):
    name = name.strip()
    email = email.strip().lower()

    if not name:
        return False, "Please enter your name."

    if not email:
        return False, "Please enter your email."

    if len(password) < 8:
        return False, "Password must contain at least 8 characters."

    password_hash, salt = hash_password(password)

    try:
        connection = get_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO users
            (name, email, password_hash, salt, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                name,
                email,
                password_hash,
                salt,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
        )

        connection.commit()
        connection.close()

        return True, "Account created successfully."

    except sqlite3.IntegrityError:
        return False, "An account with this email already exists."

    except Exception as e:
        return False, f"Could not create account: {e}"


# =========================================================
# LOGIN USER
# =========================================================

def login_user(email, password):
    email = email.strip().lower()

    connection = get_connection()
    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, name, email, password_hash, salt
        FROM users
        WHERE email = ?
        """,
        (email,)
    )

    user = cursor.fetchone()

    connection.close()

    if user is None:
        return False, "Invalid email or password.", None

    user_id = user[0]
    name = user[1]
    stored_email = user[2]
    stored_hash = user[3]
    salt = user[4]

    entered_hash, _ = hash_password(password, salt)

    if entered_hash != stored_hash:
        return False, "Invalid email or password.", None

    user_data = {
        "id": user_id,
        "name": name,
        "email": stored_email
    }

    return True, "Login successful.", user_data