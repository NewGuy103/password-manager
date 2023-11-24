# password-mgr

The `password-mgr` module provides functionalities for managing passwords, user authentication, and encryption within an SQLite database.

## Features:

### DatabaseManager Class

The `DatabaseManager` class extends `_DatabaseFunctions` and provides methods to:

- **Create User**: Add a new user to the database with a unique username and token.
- **Delete User**: Remove a user from the database based on username and token.

### UserManager Class

The `UserManager` class inherits from `_DatabaseFunctions` and facilitates:

- **Authentication**: Validate users based on credentials and manage stored passwords.
- **Entry Operations**:
  - Add new password entries.
  - Modify existing password entries.
  - Retrieve password entries based on title/identifier.
  - Delete password entries.
  - Fetch latest password entries.

## Usage:

### DatabaseManager:

Manage users within the database:

```python
from password_mgr import DatabaseManager

# Create a DatabaseManager instance
db_manager = DatabaseManager()

# Create a new user
db_manager.create_user(username="example_user", token="example_token")

# Delete a user
db_manager.delete_user(username="example_user", token="example_token")
```

### UserManager:

Handle user authentication and password management:

```python
from password_mgr import UserManager

# Create a UserManager instance
user_manager = UserManager(username="example_user", token="example_token")

# Add a new password entry
user_manager.add_entry(password_title="example_title", password_data="example_password")

# Retrieve a password entry
password = user_manager.get_entry(password_title="example_title")

# Modify a password entry
user_manager.modify_entry(password_title="example_title", password_data="new_example_password")

# Delete a password entry
user_manager.delete_entry(password_title="example_title")

# Fetch latest password entries
latest_entries = user_manager.get_latest(num=10)
```

## Graphical User Interface (GUI)

The GUI provided allows users to interact with the password management functionalities through a simple interface.
### Usage:

Run the provided GUI using `__main__.py`. The GUI offers the following functionalities:
- **Login**: Enter your username and password to access your password manager account.
- **Register**: Create a new user account with a unique username and password.
- **Manage Entries**: Add, modify, retrieve, and delete password entries securely.
- **Return to Home**: Navigate back to the home screen at any time for ease of use.

Please refer to `_gui.py` for the GUI code. No detailed documentation is available for the inner workings of the GUI code.