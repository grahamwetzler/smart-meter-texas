from __future__ import annotations

import asyncio
import datetime
import logging

import dateutil
from aiohttp import ClientSession
from tenacity import retry, retry_if_exception_type

from .const import (
    AUTH_ENDPOINT,
    BASE_ENDPOINT,
    BASE_URL,
    CLIENT_HEADERS,
    LATEST_OD_READ_ENDPOINT,
    METER_ENDPOINT,
    OD_READ_ENDPOINT,
    OD_READ_RETRY_TIME,
    TOKEN_EXPRIATION,
    USER_AGENT,
)
from .exceptions import (
    SmartMeterTexasAPIError,
    SmartMeterTexasAuthError,
    SmartMeterTexasAuthExpired,
)

__author__ = "Graham Wetzler"
__email__ = "graham@wetzler.dev"
__version__ = "0.4.1"


_LOGGER = logging.getLogger(__name__)


class Meter:
    def __init__(self, meter: str, esiid: str, address: str):
        self.meter = meter
        self.esiid = esiid
        self.address = address
        self.reading_data = None

    async def read_meter(self, client: Client):
        """Triggers an on-demand meter read and returns it when complete."""
        _LOGGER.debug("Requesting meter reading")

        # Trigger an on-demand meter read.
        await client.request(
            OD_READ_ENDPOINT, json={"ESIID": self.esiid, "MeterNumber": self.meter},
        )

        # Occasionally check to see if on-demand meter reading is complete.
        while True:
            json_response = await client.request(
                LATEST_OD_READ_ENDPOINT, json={"ESIID": self.esiid},
            )
            try:
                data = json_response["data"]
                status = data["odrstatus"]
            except KeyError:
                _LOGGER.error("Error reading meter: ", json_response)
                raise SmartMeterTexasAPIError(
                    f"Error parsing response: {json_response}"
                )
            else:
                if status == "COMPLETED":
                    _LOGGER.debug("Reading completed: %s", self.reading_data)
                    self.reading_data = data
                    return self.reading_data
                elif status == "PENDING":
                    _LOGGER.debug("Meter reading %s", status)
                    _LOGGER.debug("Sleeping for %s seconds", OD_READ_RETRY_TIME)
                    await asyncio.sleep(OD_READ_RETRY_TIME)
                else:
                    _LOGGER.error("Unknown meter reading status: %s", status)
                    raise SmartMeterTexasAPIError(f"Unknown meter status: {status}")

    @property
    def reading(self):
        """Returns the latest meter reading in kWh."""
        return float(self.reading_data["odrread"])

    @property
    def reading_datetime(self):
        """Returns the UTC datetime of the latest reading."""
        date = dateutil.parser.parse(self.reading_data["odrdate"])
        date_as_utc = date.astimezone(datetime.timezone.utc)
        return date_as_utc


class Account:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password

    async def fetch_meters(self, client: "Client"):
        """Returns a list of the meters associated with the account"""
        json_response = await client.request(METER_ENDPOINT, json={"esiid": "*"})

        meters = []
        for meter_data in json_response["data"]:
            address = meter_data["address"]
            meter = meter_data["meterNumber"]
            esiid = meter_data["esiid"]
            meter = Meter(meter, esiid, address)
            meters.append(meter)

        return meters


class Client:
    def __init__(self, websession: ClientSession, account: "Account"):
        self.websession = websession
        self.account = account
        self.token = None
        self.authenticated = False
        self.token_expiration = datetime.datetime.now()

    async def _init_websession(self):
        """Make an initial GET request to initialize the session otherwise
        future POST requests will timeout."""
        await self.websession.get(BASE_URL, headers={"User-Agent": USER_AGENT})

    def _update_token_expiration(self):
        self.token_expiration = datetime.datetime.now() + TOKEN_EXPRIATION

    @retry(retry=retry_if_exception_type(SmartMeterTexasAuthExpired))
    async def request(
        self, path: str, method: str = "post", **kwargs,
    ):
        """Helper method to make API calls against the SMT API."""
        await self.authenticate()
        resp = await self.websession.request(
            method, f"{BASE_ENDPOINT}{path}", headers=self.headers, **kwargs
        )
        if resp.status == 401:
            _LOGGER.debug("Authentication token expired; requesting new token")
            self.authenticated = False
            await self.authenticate()
            raise SmartMeterTexasAuthExpired

        # Since API call did not return a 400 code, update the token_expiration.
        self._update_token_expiration()

        json_response = await resp.json()
        return json_response

    async def authenticate(self):
        if not self.token_valid:
            _LOGGER.debug("Requesting login token")

            # Make an initial GET request otherwise subsequent calls will timeout.
            await self._init_websession()

            resp = await self.websession.request(
                "POST",
                f"{BASE_ENDPOINT}{AUTH_ENDPOINT}",
                json={
                    "username": self.account.username,
                    "password": self.account.password,
                    "rememberMe": "true",
                },
                headers=self.headers,
            )
            json_response = await resp.json()

            if resp.status == 400:
                raise SmartMeterTexasAuthError("Username or password was not accepted")

            try:
                self.token = json_response["token"]
            except KeyError:
                raise SmartMeterTexasAPIError(
                    "API returned unknown login json: %s", json_response
                )
            self._update_token_expiration()
            self.authenticated = True
            _LOGGER.debug("Successfully retrieved login token")

    @property
    def headers(self):
        headers = {**CLIENT_HEADERS}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @property
    def token_valid(self):
        if self.authenticated or (datetime.datetime.now() < self.token_expiration):
            return True

        return False
