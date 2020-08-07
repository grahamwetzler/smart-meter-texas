class SmartMeterTexasException(Exception):
    """Base exception for more specific exceptions to inherit from."""

    ...


class SmartMeterTexasAuthError(SmartMeterTexasException):
    """Exception for authentication failures.
    Either wrong username or wrong password."""

    ...


class SmartMeterTexasAuthExpired(SmartMeterTexasException):
    """Exception for when a token is no longer valid."""

    ...


class SmartMeterTexasAPIError(SmartMeterTexasException):
    """General exception for unknown API responses."""

    ...
