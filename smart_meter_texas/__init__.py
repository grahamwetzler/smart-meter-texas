from __future__ import annotations

import asyncio
import datetime
import logging
import socket
import ssl
import sys
from random import randrange

import certifi
import dateutil.parser
from aiohttp import ClientSession
from cryptography import x509
from cryptography.x509.oid import AuthorityInformationAccessOID, ExtensionOID
from dateutil.tz import gettz
from tenacity import retry, retry_if_exception_type

from .const import (
    API_DATE_ERROR,
    AUTH_ENDPOINT,
    BASE_ENDPOINT,
    BASE_HOSTNAME,
    CLIENT_HEADERS,
    INTERVAL_SYNCH,
    LATEST_OD_READ_ENDPOINT,
    METER_ENDPOINT,
    OD_READ_ENDPOINT,
    OD_READ_RETRIES,
    OD_READ_RETRY_TIME,
    TOKEN_EXPRIATION,
    USER_AGENT_TEMPLATE,
)
from .exceptions import (
    SmartMeterTexasAPIDateError,
    SmartMeterTexasAPIError,
    SmartMeterTexasAuthError,
    SmartMeterTexasAuthExpired,
    SmartMeterTexasRateLimitError,
    SmartMeterTexasTimeoutError,
)

__author__ = "Graham Wetzler"
__email__ = "graham@wetzler.dev"
__version__ = "0.5.6"

_LOGGER = logging.getLogger(__name__)


class Meter:
    def __init__(self, meter: str, esiid: str, address: str):
        self.meter = meter
        self.esiid = esiid
        self.address = address
        self.reading_data = None
        self.interval = None
        self.interval_consumption = None

    async def _latest_od_read(self, client: Client):
        """Returns the data of the latest on-demand meter read."""
        json_response = await client.request(
            LATEST_OD_READ_ENDPOINT,
            json={"ESIID": self.esiid},
        )
        try:
            data = json_response["data"]
            data["odrstatus"]
        except (KeyError, TypeError):
            _LOGGER.error("Error reading meter: %s", json_response)
            raise SmartMeterTexasAPIError(f"Error parsing response: {json_response}")
        return data

    async def read_meter(self, client: Client):
        """Triggers an on-demand meter read and returns it when complete."""
        # Record the previous reading's date so a stale reading isn't mistaken
        # for the new one; SMT can keep returning the previous reading for a
        # while after the new read is requested.
        try:
            previous_date = (await self._latest_od_read(client)).get("odrdate")
        except SmartMeterTexasAPIError:
            previous_date = None

        _LOGGER.debug("Requesting meter reading")

        # Trigger an on-demand meter read.
        await client.request(
            OD_READ_ENDPOINT,
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
        )

        # Occasionally check to see if on-demand meter reading is complete.
        for _ in range(OD_READ_RETRIES):
            _LOGGER.debug("Sleeping for %s seconds", OD_READ_RETRY_TIME)
            await asyncio.sleep(OD_READ_RETRY_TIME)

            data = await self._latest_od_read(client)
            status = data["odrstatus"]
            if status == "COMPLETED":
                if data.get("odrdate") == previous_date:
                    _LOGGER.debug("Latest reading is still the previous reading")
                elif not float(data.get("odrread") or 0):
                    _LOGGER.debug("Reading completed without a value: %s", data)
                else:
                    _LOGGER.debug("Reading completed: %s", data)
                    self.reading_data = data
                    return self.reading_data
            elif status == "PENDING":
                _LOGGER.debug("Meter reading %s", status)
            else:
                _LOGGER.error("Unknown meter reading status: %s", status)
                raise SmartMeterTexasAPIError(f"Unknown meter status: {status}")

        raise SmartMeterTexasTimeoutError(
            f"Meter reading did not complete after "
            f"{OD_READ_RETRIES * OD_READ_RETRY_TIME} seconds"
        )

    async def get_15min(self, client: Client, prevdays=1):
        """Gets the 15-minute interval data for the day `prevdays` days ago.

        Surplus generation is returned and stored in `read_15min`, and
        consumption is stored in `read_15min_consumption`. If SMT doesn't have
        data for that day yet, the day before it is used instead.
        """
        prevdays = int(prevdays)
        for days in (prevdays, prevdays + 1):
            date = (datetime.date.today() - datetime.timedelta(days=days)).strftime(
                "%m/%d/%Y"
            )
            _LOGGER.debug("Getting Interval data for %s", date)
            json_response = await client.request(
                INTERVAL_SYNCH,
                json={
                    "startDate": date,
                    "endDate": date,
                    "reportFormat": "JSON",
                    "ESIID": [self.esiid],
                    "versionDate": None,
                    "readDate": None,
                    "versionNum": None,
                    "dataType": None,
                },
            )
            try:
                data = json_response["data"]
                if "energyData" in data:
                    break
                error_message = data.get("errorMessage", "")
            except (KeyError, TypeError, AttributeError):
                error_message = None
            if not error_message or API_DATE_ERROR not in error_message:
                _LOGGER.error("Error reading data: %s", json_response)
                raise SmartMeterTexasAPIError(
                    f"Error parsing response: {json_response}"
                )
            _LOGGER.debug("No interval data for %s", date)
        else:
            raise SmartMeterTexasAPIDateError(
                "Unable to get data from SMT using the date"
            )

        surplus = []
        consumption = []
        for entry in data["energyData"]:
            intervals = self._parse_intervals(entry["DT"], entry["RD"])
            if entry["RT"] == "G":
                surplus.extend(intervals)
            elif entry["RT"] == "C":
                consumption.extend(intervals)
            else:
                _LOGGER.debug("Ignoring unknown interval type: %s", entry["RT"])

        self.interval = surplus
        self.interval_consumption = consumption
        return self.interval

    @staticmethod
    def _parse_intervals(date: str, reads: str):
        """Parses SMT's comma-separated interval reads into [time, kWh] pairs.

        SMT reports 100 slots per day. Slots 8-11 hold the repeated 1 AM hour
        when daylight saving time ends and are blank on other days, so the time
        of each slot comes from its position rather than its order.
        """
        reads = reads.split(",")
        intervals = []
        for slot, read in enumerate(reads):
            if not read:
                continue
            if len(reads) == 100 and slot >= 8:
                minutes = (slot - 4) * 15
            else:
                minutes = slot * 15
            hour, minute = divmod(minutes, 60)
            intervals.append([f"{date} {hour}:{minute:02d}", read.split("-")[0]])
        return intervals

    @property
    def reading(self):
        """Returns the latest meter reading in kWh."""
        return float(self.reading_data["odrread"])

    @property
    def reading_datetime(self):
        """Returns the UTC datetime of the latest reading.
        'odrdate' is returned from the SMT API in America/Chicago timezone."""
        date = dateutil.parser.parse(self.reading_data["odrdate"]).replace(
            tzinfo=gettz("America/Chicago")
        )
        date_as_utc = date.astimezone(datetime.timezone.utc)
        return date_as_utc

    @property
    def read_15min(self):
        """Returns the list of date/times and the surplus generation in kWh."""
        return self.interval

    @property
    def read_15min_consumption(self):
        """Returns the list of date/times and the consumption in kWh."""
        return self.interval_consumption


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
    def __init__(
        self, websession: ClientSession, account: "Account", ssl_context: ssl.SSLContext
    ):
        self.websession = websession
        self.account = account
        self.token = None
        self.authenticated = False
        self.token_expiration = datetime.datetime.now()
        self.user_agent = None
        self.ssl_context = ssl_context

    def _init_ssl_context(self):
        if self.ssl_context == None:
            new_ssl_context = ssl.create_default_context(capath=certifi.where())
            new_ssl_context.check_hostname = True
            new_ssl_context.verify_mode = ssl.CERT_REQUIRED
            if sys.version_info >= (3, 7):
                new_ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            else:
                new_ssl_context.options |= (
                    ssl.OP_NO_TLSv1
                    | ssl.OP_NO_TLSv1_1
                    | ssl.OP_NO_SSLv3
                    | ssl.OP_NO_SSLv2
                )
            self.ssl_context = new_ssl_context

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
        self,
        path: str,
        method: str = "post",
        **kwargs,
    ):
        """Helper method to make API calls against the SMT API."""
        await self.authenticate()
        resp = await self.websession.request(
            method,
            f"{BASE_ENDPOINT}{path}",
            headers=self.headers,
            **kwargs,
            ssl=self.ssl_context,
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

            resp = await self.websession.request(
                "POST",
                AUTH_ENDPOINT,
                json={
                    "username": self.account.username,
                    "password": self.account.password,
                    "rememberMe": "true",
                },
                headers=self.headers,
                ssl=self.ssl_context,
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


class ClientSSLContext:
    def get_ca_issuers_uri(self):
        """Retrieves the CA Issuers URI value"""
        ca_issuers_uri = None
        try:
            ssl_context = ssl.create_default_context(capath=certifi.where())
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(
                socket.socket(), server_hostname=BASE_HOSTNAME
            ) as s:
                s.connect((BASE_HOSTNAME, 443))
                cert_bin = s.getpeercert(True)
            cert = x509.load_der_x509_certificate(cert_bin)
            aia = cert.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            for description in aia:
                if (
                    description.access_method
                    == AuthorityInformationAccessOID.CA_ISSUERS
                ):
                    ca_issuers_uri = description.access_location.value
                    break
        except Exception as error:
            _LOGGER.error("Failed to lookup CA Issuers URI value: %s", error)
        if ca_issuers_uri:
            _LOGGER.debug("Found CA Issuers URI value: %s", ca_issuers_uri)

        return ca_issuers_uri

    async def get_issuers_certificate(self, ca_issuers_uri: str):
        """Downloads the CA Issuers Certificate file and returns the binary data"""
        certificate = None
        try:
            if ca_issuers_uri != None:
                async with ClientSession() as client:
                    async with await client.get(ca_issuers_uri) as resp:
                        if resp.status == 200:
                            certificate = await resp.read()

        except Exception as error:
            _LOGGER.error("Failed to retrieve CA Issuers URI certificate file")
            certificate = None
        return certificate

    def create_ssl_context(self, certificate: bin = None):
        """Creates the SSL Context using the CA Issuers binary data"""
        ssl_context = ssl.create_default_context(capath=certifi.where())
        try:
            if certificate:
                ssl_context.load_verify_locations(
                    cafile=certifi.where(), cadata=certificate
                )
                _LOGGER.debug("Loaded certificate file into SSL Context")
        except Exception as error:
            _LOGGER.error("Error loading certificate file into SSL Context")
            ssl_context = ssl.create_default_context(capath=certifi.where())

        # Enable strict checking
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        if sys.version_info >= (3, 7):
            ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ssl_context.options |= (
                ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
            )

        return ssl_context

    async def get_ssl_context(self):
        """Returns the default SSL Context"""
        ssl_context = None
        try:
            loop = asyncio.get_event_loop()
            ca_issuers_uri = await loop.run_in_executor(None, self.get_ca_issuers_uri)
            ca_certificate = await self.get_issuers_certificate(ca_issuers_uri)
            ssl_context = self.create_ssl_context(ca_certificate)
        except:
            ssl_context = None

        return ssl_context
