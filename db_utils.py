import sqlite3
import base64
import logging

import uuid
import traceback
import cryptography

import multiprocessing
import sys
import getpass

import argon2
import secrets

from pycrypter import CipherManager
from typing import Literal
import exceptions  # exceptions.py

_version = "1.0"
__all__ = [
    "DatabaseManager", "UserManager"
]


def _handle_exceptions(
        exc_object: Exception,
        exc_type: str | Literal["app", "db"],

        caller_name: str = ""
):
    """
    Handles exceptions by logging relevant information based on the exception type.

    Parameters:
        exc_object (Exception): The exception object to handle.
        exc_type (str | Literal["app", "db"]): The type of exception to handle, either "app" for application or "db" for database.
        caller_name (str): The name of the calling function where the exception occurred.

    Returns:
        Exception: The original exception object passed as an argument.

    Raises:
        ValueError: If an invalid exception type is provided.
    """

    if exc_type not in {'app', 'db'}:
        raise ValueError("Invalid exception type to handle")

    exc_info = traceback.format_exception(exc_object)
    tb_msg = ''.join(exc_info)

    if exc_type == "db":
        logging.error(
            f"Database transaction failed [{caller_name}]:\n"
            f"[Error Code]: {exc_object.__dict__.get('sqlite_errorcode', None)}\n"

            f"[Error Name]: {exc_object.__dict__.get('sqlite_errorname', None)}\n"
            f"[Error Message]: {tb_msg}"
        )
    elif exc_type == "app":
        logging.critical(
            f"Application error on [{caller_name}]: \n"
            f"{tb_msg}"
        )

    return exc_object


def _get_user_id(cursor: sqlite3.Cursor, username: str):
    """
    Gets the user ID associated with the provided username from the database.

    Parameters:
        cursor (sqlite3.Cursor): The cursor for database operations.
        username (str): The username to retrieve the ID for.

    Returns:
        str: The user ID associated with the username.
    """

    cursor.execute("""
        SELECT user_id FROM users
        WHERE username=?
    """, [username])
    user_id = cursor.fetchone()[0]

    return user_id


def _verify_user_token(
        cursor: sqlite3.Cursor,
        username: str,

        token: str | bytes
):
    """
    Verifies the user's token against the hashed token stored in the database.

    Parameters:
        cursor (sqlite3.Cursor): The cursor for database operations.
        username (str): The username for which the token needs verification.
        token (str | bytes): The token to be verified.

    Returns:
        bool | int:
            - True if the token is verified successfully.
            - False if the token does not match or is invalid.
            - -1 if an exception occurred during verification.
    """

    hasher = argon2.PasswordHasher()

    cursor.execute("""
        SELECT token FROM users
        WHERE username=?
    """, [username])

    hashed_token = cursor.fetchone()[0]
    try:
        hasher.verify(hashed_token, token)
    except argon2.exceptions.VerifyMismatchError:
        return False
    except Exception as app_err:
        _handle_exceptions(
            app_err, "app",
            caller_name=_verify_user_token.__name__
        )
        return -1

    return True


class _DatabaseFunctions:
    """
    Provides essential functions for database management related to user information and initialization.

    Contains methods for database initialization, checking user existence,
    closing database connections, and serving as a context manager.

    Attributes:
        db_conn: sqlite3.Connection - Represents the connection to the SQLite database.
        db_cursor: sqlite3.Cursor - Represents the cursor for database operations.
        cipher_mgr: CipherManager - Manages encryption and decryption operations.
        pw_hasher: argon2.PasswordHasher - Manages password hashing using Argon2.

    Parameters:
        database_name (str): The name of the SQLite database file.

    """

    def __init__(self, database_name="PasswordManager.db"):
        self.db_conn = sqlite3.connect(database_name, timeout=10)
        self.db_cursor = self.db_conn.cursor()

        self.cipher_mgr: CipherManager = CipherManager()
        self.pw_hasher: argon2.PasswordHasher = argon2.PasswordHasher()

        self._init_sql()

    def _init_sql(self):
        self.db_cursor.executescript("""
            PRAGMA foreign_keys = ON; 

            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,

                token TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_data (
                data_id TEXT PRIMARY KEY,
                user_id TEXT,

                username TEXT,
                password_title TEXT UNIQUE,

                password_data BLOB,
                FOREIGN KEY (username) REFERENCES users(username)
            );

            CREATE TABLE IF NOT EXISTS user_mapping (
                data_id TEXT PRIMARY KEY,
                username TEXT,

                user_id TEXT,

                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            );
        """)
        logging.info(
            f"[{type(self).__name__}]: Completed SQL initializer"
        )

    def _check_user_existence(self, username):
        """
        Checks the existence of a user in the database based on the provided username.

        Parameters:
            username (str): The username to check for existence.

        Returns:
            bool: True if the user exists, False otherwise.
        """

        self.db_cursor.execute("""
            SELECT user_id FROM users 
            WHERE username=?
        """, [username])

        result = self.db_cursor.fetchone()
        if result:
            return True

        return False

    def close(self):
        """
        Closes the database connection and commits any pending transactions.

        Returns:
            None
        """

        self.db_conn.commit()
        self.db_conn.close()

    def __enter__(self):
        """
        Serves as a context manager for database connections.
        """
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Serves as a context manager for database connections.

        Parameters:
            exc_type: Type - The type of exception.
            exc_val: Exception - The exception value.
            exc_tb: Traceback - The traceback information.

        Returns:
            bool: False
        """
        self.close()
        return False


class DatabaseManager(_DatabaseFunctions):
    """
    Manages interactions with the database for user management, including user creation and deletion.

    Inherits from `_DatabaseFunctions` and provides methods to create and delete users from the database.
    """

    def __init__(self):
        super().__init__()

    def create_user(
            self,
            username: str,

            token: str
    ):
        """
        Creates a new user in the database with the provided username and token.

        Parameters:
            username (str): The username for the new user.
            token (str): The token for the new user.

        Returns:
            bool: True if the user is created successfully, False otherwise.

        Raises:
            RuntimeError: If a user with the same name already exists.
            TypeError: If the provided username is not a string or the token is not a string or bytes.
        """

        result = self._check_user_existence(username)
        if result:
            raise RuntimeError("A user with this name already exists")

        if not isinstance(username, str):
            raise TypeError("Username must be a string")
        if not isinstance(token, str | bytes):
            raise TypeError("Token must be a string")

        hashed_token = self.pw_hasher.hash(token)
        caller_name = f"{type(self).__name__}.{self.create_user.__name__}"

        try:
            user_id = str(uuid.uuid4())
            with self.db_conn:
                self.db_cursor.execute("""
                    INSERT INTO users VALUES (
                        ?, ?, ?
                    ); 
                """, [user_id, username, hashed_token])
                self.db_cursor.execute("""
                    INSERT INTO user_mapping VALUES (
                        ?, ?, ?
                    );
                """, [str(uuid.uuid4()), username, user_id])
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
            return False
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
            return False

        logging.info(
            f"[{caller_name}]: Created new user '{username}'"
        )
        return True

    def delete_user(
            self, username: str,
            token: str | bytes
    ):
        """
        Deletes a user from the database based on the provided username and token.

        Parameters:
            username (str): The username of the user to be deleted.
            token (str | bytes): The token associated with the user.

        Returns:
            bool: True if the user is deleted successfully, False otherwise.

        Raises:
            exceptions.InvalidUserError: If the user with the provided username does not exist.
            TypeError: If the provided username is not a string or the token is not a string or bytes.
            exceptions.InvalidCredentialsError: If login and encryption credentials do not match.
        """

        result = self._check_user_existence(username)
        if not result:
            raise exceptions.InvalidUserError("A user with this name does not exist")

        if not isinstance(username, str):
            raise TypeError("Username must be a string")
        if not isinstance(token, str | bytes):
            raise TypeError("Token must be a string")

        caller_name = f"{type(self).__name__}.{self.delete_user.__name__}"
        token_valid = _verify_user_token(
            self.db_cursor, username,
            token
        )

        if not token_valid:
            raise exceptions.InvalidCredentialsError(
                "Login and encryption credentials do not match"
            )
        elif token_valid == -1:
            return False

        try:
            with self.db_conn:
                self.db_cursor.execute("""
                    DELETE FROM user_mapping
                    WHERE username=?
                """, [username])
                self.db_cursor.execute("""
                    DELETE FROM user_data
                    WHERE username=?
                """, [username])
                self.db_cursor.execute("""
                    DELETE FROM users
                    WHERE username=?
                """, [username])
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
            return False
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
            return False

        logging.info(
            f"[{caller_name}]: Deleted user '{username}'"
        )
        return True


class UserManager(_DatabaseFunctions):
    """
    Handles user management and interactions with a database for password storage.

    Inherits from `_DatabaseFunctions` and provides methods to authenticate users, manage stored passwords,
    add, retrieve, and delete password entries associated with a specific user.

    Parameters:
        username (str): The username for authentication and data retrieval.
        token (str): The token used for encryption and authentication.

    Raises:
        exceptions.NoCredentialsError: If no credentials are provided during initialization.
        exceptions.InvalidUserError: If the provided username does not exist.
        exceptions.InvalidCredentialsError: If login credentials do not match or are invalid.
    """

    def __init__(
            self,
            username: str,

            token: str
    ):
        super().__init__()
        if not username or not token:
            raise exceptions.NoCredentialsError(
                "No credentials were provided"
            )

        result = self._check_user_existence(username)
        if not result:
            raise exceptions.InvalidUserError(
                "No user with this name exists"
            )

        try:
            with self.db_conn:
                token_valid = _verify_user_token(
                    self.db_cursor, username,
                    token
                )
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=type(self).__name__
            )
            raise
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=type(self).__name__
            )
            raise

        if token_valid == -1:
            return

        if not token_valid:
            raise exceptions.InvalidCredentialsError(
                "Login credentials do not match"
            )
        self.username = username
        self._token = token
        return

    def add_entry(
            self, password_title: str,
            password_data: str | bytes
    ):
        """
        Adds a new password entry for the user.

        Parameters:
            password_title (str): Title/identifier for the password entry.
            password_data (str | bytes): The password or data to be stored, can be string or bytes.

        Returns:
            bool: True if the entry is added successfully, False otherwise.

        Raises:
            ValueError: If either password_title or password_data is missing.
            exceptions.InvalidCredentialsError: If login and encryption credentials do not match.
        """

        if not password_title or not password_data:
            raise ValueError("Password data is missing")

        caller_name = f"{type(self).__name__}.{self.add_entry.__name__}"
        token_valid = _verify_user_token(
            self.db_cursor, self.username,
            self._token
        )

        if not token_valid:
            raise exceptions.InvalidCredentialsError(
                "Login and encryption credentials do not match"
            )
        elif token_valid == -1:
            return False

        try:
            with self.db_conn:
                self.db_cursor.execute("""
                    SELECT * FROM user_data
                    WHERE username=? AND password_title=? 
                """, [self.username, password_title])

                result = self.db_cursor.fetchone()
                user_id = _get_user_id(self.db_cursor, self.username)

                encrypted_data = self.cipher_mgr.fernet.encrypt_data(
                    password_data, password=self._token
                )

                if result:
                    self.db_cursor.execute("""
                        UPDATE user_data 
                        SET password_data=? 

                        WHERE username=? AND password_title=? 
                    """, [encrypted_data, self.username, password_title])

                    logging.info(
                        f"[{caller_name}]: Modified entry '{password_title}'"
                    )
                    return True

                self.db_cursor.execute("""
                    INSERT INTO user_data
                    VALUES (?, ?, ?, ?, ?) 
                """, [
                    str(uuid.uuid4()), user_id,
                    self.username, password_title,

                    encrypted_data
                ])

                logging.info(
                    f"[{caller_name}]: Added new entry '{password_title}'"
                )
                return True
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
            return False
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
            return False

    def get_entry(self, password_title: str):
        """
        Retrieves a password entry based on the given password title.

        Parameters:
            password_title (str): Title/identifier for the password entry to retrieve.

        Returns:
            str | None: The retrieved password as a string, or None if the entry doesn't exist.

        Raises:
            ValueError: If password_title is missing.
            exceptions.InvalidCredentialsError: If login and encryption credentials do not match.
        """

        if not password_title:
            raise ValueError("Password title is missing")

        caller_name = f"{type(self).__name__}.{self.get_entry.__name__}"
        token_valid = _verify_user_token(
            self.db_cursor, self.username,
            self._token
        )

        if not token_valid:
            raise exceptions.InvalidCredentialsError(
                "Login and encryption credentials do not match"
            )
        elif token_valid == -1:
            return False

        try:
            with self.db_conn:
                self.db_cursor.execute("""
                    SELECT password_data FROM user_data
                    WHERE username=? AND password_title=? 
                """, [self.username, password_title])

                result = self.db_cursor.fetchone()
            if not result:
                return None

            decrypted_data = self.cipher_mgr.fernet.decrypt_data(
                result[0], password=self._token
            )
            password = decrypted_data.decode('utf-8')
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
            return False
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
            return False

        logging.info(
            f"[{caller_name}]: Fetched entry {self.username}:'{password_title}'"
        )
        return password

    def delete_entry(self, password_title: str):
        """
        Deletes a password entry associated with the given password title.

        Parameters:
            password_title (str): Title/identifier for the password entry to delete.

        Returns:
            bool: True if the entry is deleted successfully, False otherwise.

        Raises:
            ValueError: If password_title is missing.
            exceptions.InvalidCredentialsError: If login and encryption credentials do not match.
        """

        # method doc
        """
        Adds a new password entry for the user.

        Parameters:
            password_title (str): Title/identifier for the password entry.
            password_data (str | bytes): The password or data to be stored, can be string or bytes.

        Returns:
            bool: True if the entry is added successfully, False otherwise.

        Raises:
            ValueError: If either password_title or password_data is missing.
            exceptions.InvalidCredentialsError: If login and encryption credentials do not match.
        """

        if not password_title:
            raise ValueError("Password title is missing")

        caller_name = f"{type(self).__name__}.{self.delete_entry.__name__}"
        token_valid = _verify_user_token(
            self.db_cursor, self.username,
            self._token
        )

        if not token_valid:
            raise exceptions.InvalidCredentialsError(
                "Login and encryption credentials do not match"
            )
        elif token_valid == -1:
            return False

        try:
            with self.db_conn:
                self.db_cursor.execute("""
                    SELECT password_data FROM user_data
                    WHERE username=? AND password_title=? 
                """, [self.username, password_title])

                result = self.db_cursor.fetchone()

                if not result:
                    return None

                self.db_cursor.execute("""
                    DELETE FROM user_data
                    WHERE password_title=?
                """, [password_title])
        except sqlite3.Error as db_err:
            _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
            return False
        except Exception as app_err:
            _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
            return False

        logging.info(
            f"[{caller_name}]: Deleted entry {self.username}:'{password_title}'"
        )
        return True


# import sqlite3; db=sqlite3.connect('PasswordManager.db'); cur=db.cursor()
if __name__ == '__main__':
    raise NotImplementedError("Still working on the GUI!")

