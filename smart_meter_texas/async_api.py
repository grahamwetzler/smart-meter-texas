import asyncio
import datetime
import functools
import logging
from typing import Awaitable, Dict

import dateutil.parser
from aiohttp import ClientResponse, ClientResponseError, ClientSession

from .const import (
    API_ERROR_KEY,
    AUTH_ENDPOINT,
    BASE_ENDPOINT,
    BASE_URL,
    DASHBOARD_ENDPOINT,
    LATEST_OD_READ_ENDPOINT,
    OD_READ_ENDPOINT,
    OD_READ_RETRY_TIME,
    TOKEN_EXPIRED_KEY,
    TOKEN_EXPIRED_VALUE,
    USER_AGENT,
)

_LOGGER = logging.getLogger(__name__)


class SMTMeterReader:
    def __init__(
        self, websession: ClientSession, username: str, password: str,
    ) -> None:
        self.websession = websession
        self.username = username
        self.password = password
        self.headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.esiid = None
        self.meter = None
        self._address = None
        self._reading_data = None
        self.login_failure_count = 0

    def _auth_required(func: Awaitable) -> Awaitable:
        """Decorator function to handle authentication errors and expired
        login tokens."""

        @functools.wraps(func)
        async def auth_func(self, *args, **kwargs):
            json_response = await func(self, *args, **kwargs)
            self.raise_for_auth_error(json_response)

            if json_response.get(TOKEN_EXPIRED_KEY) == TOKEN_EXPIRED_VALUE:
                _LOGGER.debug("Login token expired")
                await self.authenticate()
                return func(self, *args, **kwargs)

            return json_response

        return auth_func

    async def _api_request(
        self, websession: ClientSession, path: str = "", method: str = "post", **kwargs,
    ) -> ClientResponse.json:
        try:
            resp = await websession.request(method, f"{BASE_ENDPOINT}{path}", **kwargs)
        except ClientResponseError as e:
            _LOGGER.error("Server responded with error code %s", e.status)
        else:
            json_response = await resp.json()
            self.raise_for_auth_error(json_response)
            return json_response

    def raise_for_auth_error(self, resp: Dict[str, object]) -> None:
        auth_error = resp.get(API_ERROR_KEY)
        if auth_error:
            _LOGGER.error("API returned error: %s", auth_error)
            raise SMTAuthError(f"Login failed: {auth_error}")

    async def _set_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    @_auth_required
    async def _get_dashboard(self) -> ClientResponse.json:
        json_response = await self._api_request(
            self.websession, DASHBOARD_ENDPOINT, headers=self.headers,
        )
        return json_response

    async def _initalize_websession(self) -> None:
        """Initializes the websession by making an initial connection."""
        await self.websession.request("get", BASE_URL, headers=self.headers)

    async def authenticate(self) -> None:

        _LOGGER.debug("Requesting login token")

        # Make an initial GET request otherwise subsequent calls will timeout
        await self._initalize_websession()

        json_response = await self._api_request(
            self.websession,
            AUTH_ENDPOINT,
            json={
                "username": self.username,
                "password": self.password,
                "rememberMe": "true",
            },
            headers=self.headers,
        )

        await self._set_token(json_response["token"])
        _LOGGER.debug("Successfully retrieved token")

    async def read_dashboard(self) -> None:
        resp = await self._get_dashboard()

        data = resp.get("data")
        meter_details = data.get("defaultMeterDetails")

        self._address = meter_details.get("address")
        self.meter = meter_details.get("meterNumber")
        self.esiid = meter_details.get("esiid")

    @_auth_required
    async def read_meter(self) -> ClientResponse.json:

        _LOGGER.debug("Requesting meter reading")

        await self._api_request(
            self.websession,
            OD_READ_ENDPOINT,
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
            headers=self.headers,
        )

        while True:
            json_response = await self._api_request(
                self.websession,
                LATEST_OD_READ_ENDPOINT,
                json={"ESIID": self.esiid},
                headers=self.headers,
            )
            data = json_response.get("data")
            status = data.get("odrstatus")
            status_reason = data.get("statusReason")
            if status_reason:
                _LOGGER.debug(status_reason)

            _LOGGER.debug("Meter reading %s", status)

            if status == "PENDING":
                _LOGGER.debug("Sleeping for %s seconds", OD_READ_RETRY_TIME)
                await asyncio.sleep(OD_READ_RETRY_TIME)
            elif status == "COMPLETED":
                self._reading_data = json_response["data"]
                _LOGGER.debug("Reading completed: %s", self._reading_data)
                return json_response

    @property
    def reading(self) -> float:
        """Return the latest reading."""
        return float(self._reading_data["odrread"])

    @property
    def reading_datetime(self) -> datetime.datetime:
        """Return the time of the latest reading."""
        _date = dateutil.parser.parse(self._reading_data["odrdate"])
        _date_as_utc = _date.astimezone(datetime.timezone.utc)
        return _date_as_utc

    @property
    def address(self) -> str:
        """Return the address associated with the meter."""
        return self._address


class SMTAuthError(Exception):
    ...
