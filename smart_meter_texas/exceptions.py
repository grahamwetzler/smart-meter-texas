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


class SmartMeterTexasAPIError(SmartMeterTexasException):
    """General exception for unknown API responses."""

    ...


class SmartMeterTexasAuthExpired(SmartMeterTexasAPIError):
    """Exception for when a token is no longer valid.

    Raised from `Client.request` when requests keep returning 401 after
    logging in again."""

    ...


class SmartMeterTexasAPIDateError(SmartMeterTexasException):
    """Exception for no data for specified date"""

    ...


class SmartMeterTexasTimeoutError(SmartMeterTexasException):
    """Exception for when an on-demand meter read does not complete in time."""

    ...
