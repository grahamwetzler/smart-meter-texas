class SmartMeterTexasException(Exception):
    """Base exception for more specific exceptions to inherit from."""

    ...


class SmartMeterTexasAuthError(SmartMeterTexasException):
    """Exception for authentication failures.
    Either wrong username or wrong password."""

    ...


class SmartMeterTexasRateLimitError(SmartMeterTexasException):
    """Exception for reaching the ratelimit.
    Either too many login attempts or too many requests."""

    ...


class SmartMeterTexasAuthExpired(SmartMeterTexasException):
    """Exception for when a token is no longer valid."""

    ...


class SmartMeterTexasAPIError(SmartMeterTexasException):
    """General exception for unknown API responses."""

    ...


class SmartMeterTexasAPIDateError(SmartMeterTexasException):
    """Exception for no data for specified date"""

    ...
