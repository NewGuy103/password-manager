class Error(Exception):
    pass


class ExistingUser(Error):
    pass


class InvalidUser(Error):
    pass


class NoCredentialsError(Error):
    pass


class InvalidCredentialsError(Error):
    pass

