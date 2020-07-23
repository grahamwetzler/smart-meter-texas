import asyncio
import datetime
import logging

import dateutil.parser
from aiohttp import ClientResponse, ClientResponseError, ClientSession

from .const import (
    ON_DEMAND_READ_RETRY_TIME,
    API_ERROR_KEY,
    TOKEN_EXPIRED_KEY,
    TOKEN_EXPIRED_VALUE,
    URL,
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

    async def _api_request(
        self, websession: ClientSession, path: str = "", method: str = "post", **kwargs,
    ) -> ClientResponse.json:
        try:
            resp = await websession.request(method, f"{URL}{path}", **kwargs)
        except ClientResponseError as e:
            _LOGGER.error("Server responded with error %s", e.status)
        else:
            json_response = await resp.json()
            auth_error = json_response.get(API_ERROR_KEY)
            if auth_error:
                _LOGGER.error("API returned error: %s", auth_error)
                raise SMTAuthError(f"Login failed: {auth_error}")
            elif json_response.get(TOKEN_EXPIRED_KEY) == TOKEN_EXPIRED_VALUE:
                _LOGGER.debug("Login token expired")
                _LOGGER.warning("Login has failed %s time(s)", self.login_failure_count)
                if self.login_failure_count >= 2:
                    raise SMTAuthError
                else:
                    self.login_failure_count += 1

                self.authenticate()

            return json_response

    async def _set_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    async def _get_dashboard(self) -> ClientResponse.json:
        json_response = await self._api_request(
            self.websession, "api/dashboard", headers=self.headers,
        )
        return json_response

    async def _initalize_websession(self) -> None:
        """Initializes the websession by making an initial connection."""
        await self.websession.request("get", URL, headers=self.headers)

    async def authenticate(self) -> ClientSession:

        _LOGGER.debug("Requesting login token")

        # Make an initial GET request otherwise subsequent calls will timeout
        await self._initalize_websession()

        json_response = await self._api_request(
            self.websession,
            "api/user/authenticate",
            json={
                "username": self.username,
                "password": self.password,
                "rememberMe": "true",
            },
            headers=self.headers,
        )

        await self._set_token(json_response["token"])
        _LOGGER.debug("Successfully retrieved token")

        return self.websession

    async def read_dashboard(self) -> None:
        resp = await self._get_dashboard()

        data = resp.get("data")
        meter_details = data.get("defaultMeterDetails")

        self._address = meter_details.get("address")
        self.meter = meter_details.get("meterNumber")
        self.esiid = meter_details.get("esiid")

    async def read_meter(self) -> None:

        _LOGGER.debug("Requesting meter reading")

        await self._api_request(
            self.websession,
            "/api/ondemandread",
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
            headers=self.headers,
        )

        while True:
            json_response = await self._api_request(
                self.websession,
                "api/usage/latestodrread",
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
                await asyncio.sleep(ON_DEMAND_READ_RETRY_TIME)
            elif status == "COMPLETED":
                self._reading_data = json_response["data"]
                break

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
