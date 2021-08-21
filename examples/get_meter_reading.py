"""Example to show how to read each meter associated with a user's account."""

import asyncio
import logging
import os
import sys

import aiohttp
import get_ssl_context as get_ssl
import pytz

from smart_meter_texas import Account, Client

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]

timezone = pytz.timezone("America/Chicago")


async def main():

    context = get_ssl.get_ssl_context()

    async with aiohttp.ClientSession() as websession:
        account = Account(username, password)
        client = Client(websession, account, ssl_context=context)

        print("Authenticating...")
        await client.authenticate()

        meters = await account.fetch_meters(client)

        for meter in meters:
            print("Reading meter...")
            await meter.read_meter(client)

            localized_time = meter.reading_datetime.astimezone(timezone)
            print(f"{meter.reading:,.0f} kW @ {localized_time}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
