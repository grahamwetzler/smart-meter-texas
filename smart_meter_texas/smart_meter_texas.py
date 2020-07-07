import asyncio
import datetime
import logging

import dateutil.parser
from aiohttp import ClientResponse, ClientSession

URL = "https://www.smartmetertexas.com/"
DEFAULT_TIMEOUT = 15
ON_DEMAND_READ_RETRY_TIME = 15


class Auth:
    def __init__(
        self,
        websession: ClientSession,
        username: str,
        password: str,
        default_timeout: int = DEFAULT_TIMEOUT,
    ):
        self.websession = websession
        self.username = username
        self.password = password
        self.default_timeout = default_timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14;\
                 rv:77.0) Gecko/20100101 Firefox/77.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def _set_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    async def _initalize_websession(self) -> None:
        """Initalizes the websesion by making an inital connection."""
        await self.websession.request(
            "get", URL, headers=self.headers, timeout=self.default_timeout
        )

    async def authenticate(self) -> ClientSession:
        await self._initalize_websession()
        resp = await self.websession.request(
            "post",
            f"{URL}api/user/authenticate",
            json={
                "username": self.username,
                "password": self.password,
                "rememberMe": "true",
            },
            headers=self.headers,
            timeout=self.default_timeout,
        )

        if resp.status != 200:
            raise SMTError()

        json_response = await resp.json()
        await self._set_token(json_response["token"])

        return self.websession


class Meter:
    """Class representation of a smart meter."""

    def __init__(self, auth: Auth, esiid: str, meter: str):
        self.auth = auth.websession
        self.headers = auth.headers
        self.esiid = esiid
        self.meter = meter
        self._reading_data = None

    async def _request_odr(self) -> ClientResponse.json:
        resp = await self.auth.request(
            "post",
            f"{URL}/api/ondemandread",
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
            headers=self.headers,
            timeout=DEFAULT_TIMEOUT,
        )
        return await resp.json()

    async def _get_latest_odr(self) -> ClientResponse.json:
        resp = await self.auth.request(
            "post",
            f"{URL}api/usage/latestodrread",
            json={"ESIID": self.esiid},
            headers=self.headers,
            timeout=DEFAULT_TIMEOUT,
        )
        return await resp.json()

    async def async_read_meter(self):
        await self._request_odr()
        while True:
            reading = await self._get_latest_odr()
            status = reading.get("data").get("odrstatus")
            status_reason = reading.get("data").get("statusReason")
            if status_reason:
                logging.debug(reading)

            if status == "PENDING":
                await asyncio.sleep(ON_DEMAND_READ_RETRY_TIME)
            elif status == "COMPLETED":
                self._reading_data = reading["data"]
                break
            else:
                raise SMTError(reading)

    @property
    def reading(self) -> float:
        """Return the latest reading."""
        return float(self._reading_data["odrread"])

    @property
    def reading_datetime(self) -> datetime.datetime:
        """Return the time of the latest reading."""
        return dateutil.parser.parse(self._reading_data["odrdate"]).astimezone(
            tz=datetime.timezone.utc
        )


class SMTError(Exception):
    pass
