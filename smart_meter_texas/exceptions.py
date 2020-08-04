class SmartMeterTexasException(Exception):
    ...


class SmartMeterTexasAuthError(SmartMeterTexasException):
    ...


class SmartMeterTexasAuthExpired(SmartMeterTexasException):
    ...


class SmartMeterTexasAPIError(SmartMeterTexasException):
    ...
