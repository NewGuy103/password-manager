import sqlite3
import base64
import logging

import uuid
import traceback
import cryptography

import multiprocessing
import sys

from pycrypter import CipherManager
from typing import Literal
import exceptions

__all__ = [
    "DatabaseManager"
]


def _handle_exceptions(
        exc_object: Exception,
        exc_type: str | Literal["app", "db"],

        caller_name: str = ""
):
    if exc_type not in {'app', 'db'}:
        raise ValueError("Invalid exception type to handle")

    if exc_type == "db":
        exc_info = traceback.format_exception(exc_object)
        tb_msg = ''.join(exc_info)

        logging.error(
            f"Database transaction failed [{caller_name}]:\n"
            f"[Error Code]: {exc_object.__dict__.get('sqlite_errorcode', None)}\n"
    
            f"[Error Name]: {exc_object.__dict__.get('sqlite_errorname', None)}\n"
            f"[Error Message]: {tb_msg}"
        )
    elif exc_type == "app":
        exc_info = traceback.format_exception(exc_object)
        tb_msg = ''.join(exc_info)

        logging.critical(
            f"Application error on [{caller_name}]: \n"
            f"{tb_msg}"
        )

    return [None, exc_object]


def _get_user_id(cursor, username):
    cursor.execute("""
        SELECT user_id FROM users
        WHERE username=?
    """, [username])
    user_id = cursor.fetchone()[0]

    return user_id


class _DatabaseFunctions:
    def __init__(self, database_name="PasswordManager.db"):
        self.db_conn = sqlite3.connect(database_name, timeout=10)
        self.db_cursor = self.db_conn.cursor()

        self.cipher_mgr: CipherManager = CipherManager()
        self._init_sql()

    def _init_sql(self):
        self.db_cursor.executescript("""
            PRAGMA foreign_keys = ON; 

            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE,

                encrypted_token BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS user_data (
                data_id TEXT PRIMARY KEY,
                user_id TEXT,

                username TEXT,
                password_title TEXT,

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
        self.db_cursor.execute("""
            SELECT user_id FROM users 
            WHERE username=?
        """, [username])

        result = self.db_cursor.fetchone()
        if result:
            return True

        return False

    def close(self):
        self.db_conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
        return False


class DatabaseManager(_DatabaseFunctions):
    def __init__(self):
        super().__init__()

    def create_user(
            self,
            username: str,

            token: str
    ):
        result = self._check_user_existence(username)
        if result:
            return [None, exceptions.ExistingUser("A user with this name already exists")]

        if not isinstance(username, str):
            raise TypeError("Username must be a string")

        if not isinstance(token, str | bytes):
            raise TypeError("Token must be a string")

        encrypted_token = self.cipher_mgr.fernet.encrypt_data(
            token, password=token
        )
        caller_name = f"{type(self).__name__}.{self.create_user.__name__}"
        try:
            user_id = str(uuid.uuid4())
            with self.db_conn:
                self.db_cursor.execute("""
                    INSERT INTO users VALUES (
                        ?, ?, ?
                    ); 
                """, [user_id, username, encrypted_token])
                self.db_cursor.execute("""
                    INSERT INTO user_mapping VALUES (
                        ?, ?, ?
                    );
                """, [str(uuid.uuid4()), username, user_id])
        except sqlite3.Error as db_err:
            return _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
        except Exception as app_err:
            return _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )

        logging.info(
            f"[{caller_name}]: Created new user '{username}'"
        )
        return [True, None]


class UserManager(_DatabaseFunctions):
    def __init__(
            self,
            username: str,

            token: str
    ):
        super().__init__()
        if not username or not token:
            raise exceptions.NoCredentialsError(
                "No credentials were provided for decryption"
            )

        result = self._check_user_existence(username)
        if not result:
            raise exceptions.InvalidUser(
                "No user with this name exists"
            )

        try:
            with self.db_conn:
                self.db_cursor.execute("""
                    SELECT encrypted_token FROM users
                    WHERE username=?
                """, [username])
                result = self.db_cursor.fetchone()

            self.cipher_mgr.fernet.decrypt_data(
                result[0], password=token
            )
            self._token = token
        except cryptography.fernet.InvalidToken:
            raise exceptions.InvalidCredentialsError(
                "Password provided is not the same password "
                "used for encryption"
            ) from None
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

        self.username = username
        return

    def add_entry(
            self, password_title: str,
            password_data: str | bytes
    ):
        if not password_title or not password_data:
            return [None, ValueError("Password data is missing")]

        caller_name = f"{type(self).__name__}.{self.add_entry.__name__}"
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
                if not result:
                    self.db_cursor.execute("""
                        UPDATE user_data 
                        SET password_data=? 
                        
                        WHERE username=? AND password_title=? 
                    """, [encrypted_data, self.username, password_title])

                    logging.info(
                        f"[{caller_name}]: Added new entry '{password_title}'"
                    )
                else:
                    self.db_cursor.execute("""
                        INSERT INTO user_data
                        VALUES (?, ?, ?, ?, ?) 
                    """, [
                        str(uuid.uuid4()), user_id,
                        self.username, password_title,

                        encrypted_data
                    ])

                    logging.info(
                        f"[{caller_name}]: Modified entry '{password_title}'"
                    )
        except sqlite3.Error as db_err:
            return _handle_exceptions(
                db_err, "db",
                caller_name=caller_name
            )
        except Exception as app_err:
            return _handle_exceptions(
                app_err, "db",
                caller_name=caller_name
            )
        return [True, None]


if __name__ == '__main__':
    pw = "PassWord"
    logging.basicConfig(
        stream=sys.stdout,
        level=logging.DEBUG
    )
    db_mgr = DatabaseManager()

    success, error = db_mgr.create_user("PopeKent", pw)
    user_mgr = UserManager('PopeKent', pw)

    user_mgr.add_entry(
        "Example.com", 'MyPassIsWord!'
    )