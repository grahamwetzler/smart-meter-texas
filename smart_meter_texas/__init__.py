from __future__ import annotations

import asyncio
import binascii
import datetime
import logging
import socket
import ssl
from random import randrange

import asn1
import certifi
import dateutil.parser
import OpenSSL.crypto as crypto
from aiohttp import ClientSession
from tenacity import retry, retry_if_exception_type

from .const import (
    AUTH_ENDPOINT,
    BASE_ENDPOINT,
    BASE_HOSTNAME,
    BASE_URL,
    CLIENT_HEADERS,
    INTERVAL_SYNCH,
    LATEST_OD_READ_ENDPOINT,
    METER_ENDPOINT,
    OD_READ_ENDPOINT,
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
)

__author__ = "Graham Wetzler"
__email__ = "graham@wetzler.dev"
__version__ = "0.5.2"

_LOGGER = logging.getLogger(__name__)


class Meter:
    def __init__(self, meter: str, esiid: str, address: str):
        self.meter = meter
        self.esiid = esiid
        self.address = address
        self.reading_data = None
        self.interval = None

    async def read_meter(self, client: Client):
        """Triggers an on-demand meter read and returns it when complete."""
        _LOGGER.debug("Requesting meter reading")

        # Trigger an on-demand meter read.
        await client.request(
            OD_READ_ENDPOINT,
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
        )

        # Occasionally check to see if on-demand meter reading is complete.
        while True:
            json_response = await client.request(
                LATEST_OD_READ_ENDPOINT,
                json={"ESIID": self.esiid},
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

    async def get_15min(self, client: Client, prevdays=1):
        """Get the interval data to parse out Surplus Generation"""
        retry = 1
        prevdays = int(prevdays)
        if prevdays == 1:
            yesterday = (datetime.date.today() - datetime.timedelta(days=1)).strftime(
                "%m/%d/%Y"
            )
        else:
            yesterday = (
                datetime.date.today() - datetime.timedelta(days=prevdays)
            ).strftime("%m/%d/%Y")
        while retry < 3:
            _LOGGER.debug("Getting Interval data")
            surplus = []

            json_response = await client.request(
                INTERVAL_SYNCH,
                json={
                    "startDate": yesterday,
                    "endDate": yesterday,
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
                energy = data["energyData"]
            except KeyError:
                _LOGGER.error("Error reading data: ", json_response)
                if data["errorCode"] == "1":
                    tdsp = "TDSP" in data["errorMessage"]
                    if tdsp:
                        retry += 1
                        yesterday = (
                            datetime.date.today() - datetime.timedelta(days=retry)
                        ).strftime("%m/%d/%Y")
                        if retry < 3:
                            continue
                        else:
                            raise SmartMeterTexasAPIDateError(
                                "Unable to get data from SMT using the date"
                            )
                    else:
                        raise SmartMeterTexasAPIError(
                            f"Error parsing response: {json_response}"
                        )
            else:
                hour = -1
                minute_check = 0
                for entry in energy:
                    if entry["RT"] == "G":
                        readdata = entry["RD"].split(",")
                        for generated in readdata:
                            if generated != "":
                                if minute_check % 4 == 0:
                                    hour += 1
                                    minute = "00"
                                elif minute_check % 4 == 1:
                                    minute = "15"
                                elif minute_check % 4 == 2:
                                    minute = 30
                                elif minute_check % 4 == 3:
                                    minute = 45
                                minute_check += 1
                                num = generated.split("-")[0]
                                surplus.append([f"{yesterday} {hour}:{minute}", num])
                                self.interval = surplus
                        return self.interval

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

    @property
    def read_15min(self):
        """Returns the list of date/times and the consumption rate"""
        return self.interval


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
            new_ssl_context.options |= (
                ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
            )
            self.ssl_context = new_ssl_context

    async def _init_websession(self):
        """Make an initial GET request to initialize the session otherwise
        future POST requests will timeout."""
        self._init_ssl_context()
        await self.websession.get(
            BASE_URL, headers=self._agent_headers(), ssl=self.ssl_context
        )

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
    def _asn1_value_to_string(self, tag_number, value):
        """Retrieves the ASN.1 value as a string value"""
        if tag_number == asn1.Numbers.ObjectIdentifier:
            return value
        elif isinstance(value, bytes):
            return "0x" + str(binascii.hexlify(value).upper())
        elif isinstance(value, str):
            return value
        else:
            return repr(value)

    def _find_ca_issuers_uri(self, input_stream, tag_ca_issuers_uri_found=False):
        """Lookup the CA Issuers - URI Object and return the value."""
        ca_issuers_uri = None
        while not input_stream.eof() and not ca_issuers_uri:
            tag = input_stream.peek()
            if tag.typ == asn1.Types.Primitive:
                tag, value = input_stream.read()

                if tag_ca_issuers_uri_found:
                    str_value = self._asn1_value_to_string(tag.nr, value)
                    if str_value:
                        ca_issuers_uri = str_value.decode("utf-8")
                        tag_ca_issuers_uri_found = False
                        break
                    else:
                        tag_ca_issuers_uri_found = False

                elif self._asn1_value_to_string(tag.nr, value) == "1.3.6.1.5.5.7.48.2":
                    tag_ca_issuers_uri_found = True

            elif tag.typ == asn1.Types.Constructed:
                input_stream.enter()
                ca_issuers_uri = self._find_ca_issuers_uri(
                    input_stream, tag_ca_issuers_uri_found
                )
                input_stream.leave()

        return ca_issuers_uri

    def get_ca_issuers_uri(self):
        """Retrieves the CA Issuers URI value"""
        ca_issuers_uri = None
        ssl_context = None
        try:
            ssl_context = ssl.create_default_context(capath=certifi.where())
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
            with ssl_context.wrap_socket(
                socket.socket(), server_hostname=BASE_HOSTNAME
            ) as s:
                try:
                    s.connect((BASE_HOSTNAME, 443))
                    cert_bin = s.getpeercert(True)
                    x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
                    for idx in range(x509.get_extension_count()):
                        ext = x509.get_extension(idx)
                        short_name = ext.get_short_name()
                        if short_name == b"authorityInfoAccess":
                            decoder = asn1.Decoder()
                            data = ext.get_data()
                            decoder.start(data)
                            ca_issuers_uri = self._find_ca_issuers_uri(decoder, False)
                finally:
                    s.close()
        except Exception as error:
            _LOGGER.error("Failed to lookup CA Issuers URI value")
            ca_issuers_uri = None
        finally:
            if ca_issuers_uri:
                _LOGGER.debug("Found CA Issuers URI value: " + ca_issuers_uri)

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
        # Disable SSL, TLSv1, TLSv1.1
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
