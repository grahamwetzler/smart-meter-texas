from __future__ import annotations

import asyncio
import datetime
import logging
from random import randrange
from aiohttp.http import RESPONSES

import dateutil
import certifi
import ssl
import socket
import hashlib
from aiohttp import ClientSession, Fingerprint
from tenacity import retry, retry_if_exception_type

from .const import (
    BASE_HOSTNAME,
    AUTH_ENDPOINT,
    BASE_ENDPOINT,
    BASE_URL,
    CLIENT_HEADERS,
    LATEST_OD_READ_ENDPOINT,
    METER_ENDPOINT,
    OD_READ_ENDPOINT,
    OD_READ_RETRY_TIME,
    TOKEN_EXPRIATION,
    USER_AGENT_TEMPLATE,
)
from .exceptions import (
    SmartMeterTexasAPIError,
    SmartMeterTexasAuthError,
    SmartMeterTexasRateLimitError,
    SmartMeterTexasAuthExpired,
)

__author__ = "Graham Wetzler"
__email__ = "graham@wetzler.dev"
__version__ = "0.4.4"


_LOGGER = logging.getLogger(__name__)

# This is the SSL fingerprint for smartmetertexas.com as of 2021-08-14T01:35:00-05:00
# This logic will toggle the use of the fingerprint for SSL validation until it expires on 2021-10-14T12:00:00-00:00
_smt_known_fingerprint = b'\x39\x3B\x70\xA0\xD8\xF9\x01\x83\x36\x3F\x89\xB0\x31\x30\x90\xE6\xB9\xC8\xD1\x3B\xFD\xB7\x05\xA1\x05\x53\xE4\xA5\xD8\x92\x91\xF3'
_smt_known_fingerprint_expires = datetime.datetime(2021, 10, 14, 12, 0, 0, 0, datetime.timezone(datetime.timedelta(hours=0), name="GMT"))


_smt_current_fingerprint = None

_lookupContext = ssl.create_default_context(capath=certifi.where())
_lookupContext.check_hostname = False
_lookupContext.verify_mode = ssl.CERT_NONE

_lookupSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
_lookupSock.settimeout(1)
_wrappedLookupSock = _lookupContext.wrap_socket(_lookupSock)

try:
    """Attempts to establish an SSL connection as a test."""
    _wrappedLookupSock.connect((BASE_HOSTNAME, 443))
except:
    """The SSL connection failed, likely due to a certificate chain issue."""
    #Lookup failed
    pass
finally:
    """The SLL connection was successful, determine the current SSL Certificate fingerprint."""
    _lookupDerCertBin = _wrappedLookupSock.getpeercert(binary_form=True)
    #_lookupPemCert = ssl.DER_cert_to_PEM_cert(_wrappedLookupSock.getpeercert(True))
    _smt_current_fingerprint = hashlib.sha256(_lookupDerCertBin).digest()
    print("Known SSL Certificate SHA256 Fingerprint: " + _smt_known_fingerprint.hex())
    print("Current SSL Certificate SHA256 Fingerprint: " + _smt_current_fingerprint.hex())


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
        self.user_agent = None
        self.sslcontext = None

    def _init_sslcontext(self):
        # Check if known fingerprint is expired
        if ((_smt_current_fingerprint == None or _smt_known_fingerprint.hex() == _smt_current_fingerprint.hex()) and datetime.datetime.utcnow().timestamp() < _smt_known_fingerprint_expires.timestamp()):
            _LOGGER.debug("Proceeding with known SSL fingerprint until " + _smt_known_fingerprint_expires.isoformat())
            self.sslcontext = Fingerprint(_smt_known_fingerprint)
        else:
            _LOGGER.debug("Proceeding with normal SSL logic")
            self.sslcontext = ssl.create_default_context(capath=certifi.where())
            # Force TLSv1_2 and TLSv1_3
            self.sslcontext.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2

    async def _init_websession(self):
        """Make an initial GET request to initialize the session otherwise
        future POST requests will timeout."""
        self._init_sslcontext()
        await self.websession.get(BASE_URL, headers=self._agent_headers(), ssl=self.sslcontext)

    def _agent_headers(self):
        """Build the user agent header."""
        if not self.user_agent:
            self.user_agent = USER_AGENT_TEMPLATE.format(
                BUILD=randrange(1001, 9999), REV=randrange(12, 999)
            )

        return {"User-Agent": self.user_agent}

    def _update_token_expiration(self):
        self.token_expiration = datetime.datetime.now() + TOKEN_EXPRIATION

    @retry(retry=retry_if_exception_type(SmartMeterTexasAuthExpired))
    async def request(
        self, path: str, method: str = "post", **kwargs,
    ):
        """Helper method to make API calls against the SMT API."""
        await self.authenticate()
        resp = await self.websession.request(
            method, f"{BASE_ENDPOINT}{path}", headers=self.headers, **kwargs, ssl=self.sslcontext
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
                ssl=self.sslcontext
            )

            if resp.status == 400:
                raise SmartMeterTexasAuthError("Username or password was not accepted")

            if resp.status == 403:
                raise SmartMeterTexasRateLimitError(
                    "Reached ratelimit or brute force protection"
                )

            json_response = await resp.json()

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
        headers = {**self._agent_headers(), **CLIENT_HEADERS}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @property
    def token_valid(self):
        if self.authenticated or (datetime.datetime.now() < self.token_expiration):
            return True

        return False

