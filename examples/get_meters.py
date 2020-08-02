"""Example to show how to fetch all meters associated with a user's account."""

import asyncio
import logging
import os
import sys

import aiohttp

from smart_meter_texas import Account, Client

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]


async def main():
    async with aiohttp.ClientSession() as websession:
        account = Account(username, password)
        client = Client(websession, account)
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
