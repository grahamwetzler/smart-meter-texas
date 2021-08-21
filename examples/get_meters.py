"""Example to show how to fetch all meters associated with a user's account."""

import asyncio
import logging
import os
import sys

import aiohttp
import get_ssl_context as get_ssl

from smart_meter_texas import Account, Client

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]


async def main():

    context = get_ssl.get_ssl_context()

    async with aiohttp.ClientSession() as websession:
        account = Account(username, password)
        client = Client(websession, account, ssl_context=context)
        await client.authenticate()
        meters = await account.fetch_meters(client)

        for i, meter in enumerate(meters, 1):
            print(f"Meter {i}:")
            print(f"  Meter:\t{meter.meter}")
            print(f"  ESIID:\t{meter.esiid}")
            print(f"  Address:\t{meter.address}\n")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
