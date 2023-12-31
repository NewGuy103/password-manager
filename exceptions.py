class Error(Exception):
    pass


class ExistingUserError(Error):
    pass


class InvalidUserError(Error):
    pass


class NoCredentialsError(Error):
    pass


class InvalidCredentialsError(Error):
    pass


class NoDataError(Error):
    pass


class DataExistsError(Error):
    pass

