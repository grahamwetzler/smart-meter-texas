import asyncio
import datetime
import logging

import dateutil.parser
from aiohttp import ClientResponse, ClientSession, ClientResponseError

URL = "https://www.smartmetertexas.com/"
ON_DEMAND_READ_RETRY_TIME = 15
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14;"
    "rv:77.0) Gecko/20100101 Firefox/77.0"
)

_LOGGER = logging.getLogger(__name__)


class SMTMeterReader:
    def __init__(
        self, websession: ClientSession, username: str, password: str,
    ) -> None:
        self.websession = websession
        self.username = username
        self.password = password
        self.authenticated = False
        self.headers = {
            "User-Agent": USER_AGENT,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.esiid = None
        self.meter = None
        self._address = None
        self._reading_data = None

    async def _api_request(
        self, websession: ClientSession, path: str = "", method: str = "post", **kwargs,
    ) -> ClientResponse:
        try:
            return await websession.request(
                method,
                f"{URL}{path}",
                json=kwargs.get("json"),
                headers=kwargs.get("headers"),
            )
        except ClientResponseError as e:
            _LOGGER.warning("Server responded error code %s" % e.status)
            if e.status == 401:
                self.authenticated = False

    async def _set_token(self, token: str) -> None:
        self.headers["Authorization"] = f"Bearer {token}"

    async def _get_dashboard(self) -> ClientResponse.json:
        resp = await self._api_request(
            self.websession, "api/dashboard", headers=self.headers,
        )
        return await resp.json()

    async def authenticate(self) -> ClientSession:

        # Make an inital GET request otherwise subsequent calls will timeout
        await self._api_request(
            self.websession, method="get", headers=self.headers,
        )
        resp = await self._api_request(
            self.websession,
            "api/user/authenticate",
            json={
                "username": self.username,
                "password": self.password,
                "rememberMe": "true",
            },
            headers=self.headers,
        )

        json_response = await resp.json()

        if json_response.get("errormessage") or resp.status != 200:
            _LOGGER.error(
                "Error authenticating: %s" % json_response.get("errormessage", "")
            )
            raise SMTError

        await self._set_token(json_response["token"])
        self.authenticated = True

        return self.websession

    async def read_dashboard(self) -> None:
        resp = await self._get_dashboard()

        data = resp.get("data")
        meter_details = data.get("defaultMeterDetails")

        self._address = meter_details.get("address")
        self.meter = meter_details.get("meterNumber")
        self.esiid = meter_details.get("esiid")

    async def read_meter(self) -> None:
        await self._api_request(
            self.websession,
            "/api/ondemandread",
            json={"ESIID": self.esiid, "MeterNumber": self.meter},
            headers=self.headers,
        )
        while True:
            reading = await self._api_request(
                self.websession,
                "api/usage/latestodrread",
                json={"ESIID": self.esiid},
                headers=self.headers,
            )
            json_response = await reading.json()
            data = json_response.get("data")
            status = data.get("odrstatus")
            status_reason = data.get("statusReason")
            if status_reason:
                _LOGGER.debug(reading)

            if status == "PENDING":
                await asyncio.sleep(ON_DEMAND_READ_RETRY_TIME)
            elif status == "COMPLETED":
                self._reading_data = json_response["data"]
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
        _date = dateutil.parser.parse(self._reading_data["odrdate"])
        _date_as_utc = _date.astimezone(datetime.timezone.utc)
        return _date_as_utc

    @property
    def address(self) -> str:
        """Return the address associated with the meter."""
        return self._address


class SMTError(Exception):
    pass
