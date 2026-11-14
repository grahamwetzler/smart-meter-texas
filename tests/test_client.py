"""Tests for Client authentication and 401 handling."""

import datetime

import pytest

import smart_meter_texas
from smart_meter_texas import Account, Client, Meter
from smart_meter_texas.const import AUTH_ENDPOINT, AUTH_EXPIRED_ATTEMPTS
from smart_meter_texas.exceptions import (
    SmartMeterTexasAPIError,
    SmartMeterTexasAuthExpired,
)


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status = status
        self._payload = payload or {}
        self.released = False

    async def json(self):
        return self._payload

    def release(self):
        self.released = True


class FakeSession:
    """Returns queued API responses and records every request made."""

    def __init__(self, api_statuses):
        self.api_statuses = list(api_statuses)
        self.logins = 0
        self.api_calls = []
        self.responses = []
        self.on_api_request = None

    async def request(self, method, url, headers=None, **kwargs):
        if url == AUTH_ENDPOINT:
            self.logins += 1
            return FakeResponse(200, {"token": f"token-{self.logins}"})
        self.api_calls.append(headers.get("Authorization"))
        if self.on_api_request:
            self.on_api_request()
        status = self.api_statuses.pop(0) if self.api_statuses else 200
        resp = FakeResponse(status, {"data": "ok"})
        self.responses.append(resp)
        return resp


def make_client(session):
    return Client(session, Account("user", "pass"), ssl_context=None)


async def test_401_after_recent_success_logs_in_again():
    """A 401 shortly after a successful request must still log in again."""
    session = FakeSession([200, 401, 200])
    client = make_client(session)

    await client.request("/path")
    assert client.token_expiration > datetime.datetime.now()

    assert await client.request("/path") == {"data": "ok"}
    assert session.logins == 2
    assert session.api_calls == [
        "Bearer token-1",
        "Bearer token-1",
        "Bearer token-2",
    ]


async def test_persistent_401_is_bounded():
    session = FakeSession([401] * 100)
    client = make_client(session)

    with pytest.raises(SmartMeterTexasAuthExpired):
        await client.request("/path")

    assert len(session.api_calls) == AUTH_EXPIRED_ATTEMPTS
    assert session.logins == AUTH_EXPIRED_ATTEMPTS


async def test_auth_expired_is_an_api_error():
    session = FakeSession([401] * 100)
    client = make_client(session)

    with pytest.raises(SmartMeterTexasAPIError):
        await client.request("/path")


async def test_401_response_is_released():
    session = FakeSession([401, 200])
    client = make_client(session)

    await client.request("/path")

    assert session.responses[0].released


async def test_401_does_not_discard_token_replaced_concurrently():
    """A stale 401 must not invalidate a token another request just got."""
    session = FakeSession([401, 200])
    client = make_client(session)
    await client.authenticate()

    def replace_token():
        # Simulate a concurrent request logging in while this one is in flight.
        session.on_api_request = None
        client.token = "token-concurrent"

    session.on_api_request = replace_token

    await client.request("/path")

    assert session.logins == 1
    assert session.api_calls == ["Bearer token-1", "Bearer token-concurrent"]
    assert client.token == "token-concurrent"


async def test_cleared_token_is_not_valid_after_concurrent_success():
    """A concurrent 200 extending expiry must not revive a cleared token."""
    session = FakeSession([])
    client = make_client(session)
    await client.authenticate()

    # A 401 cleared the token, then another in-flight request that sent the
    # old token got a 200 and extended token_expiration.
    client.token = None
    client.authenticated = False
    client._update_token_expiration()
    assert not client.token_valid

    assert await client.request("/path") == {"data": "ok"}
    assert session.logins == 2
    assert session.api_calls == ["Bearer token-2"]


async def test_read_meter_does_not_swallow_persistent_401(monkeypatch):
    session = FakeSession([401] * 100)
    client = make_client(session)
    meter = Meter("meter", "esiid", "address")

    async def no_sleep(_):
        pass

    monkeypatch.setattr(smart_meter_texas.asyncio, "sleep", no_sleep)

    with pytest.raises(SmartMeterTexasAuthExpired):
        await meter.read_meter(client)

    assert session.logins == AUTH_EXPIRED_ATTEMPTS
