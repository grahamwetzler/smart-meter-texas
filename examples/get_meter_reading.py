import asyncio
import os

import aiohttp

from smart_meter_texas.async_api import Auth, Meter

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]
meter_num = os.environ["SMTMETER"]
esiid = os.environ["SMTESIID"]


async def main():
    async with aiohttp.ClientSession() as websession:
        auth = Auth(websession, username, password)
        await auth.authenticate()

        meter = Meter(auth, esiid, meter_num)
        await meter.async_read_meter()

        print(f"{meter.reading} kW @ {meter.reading_datetime}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
