import asyncio
import os

import aiohttp
import pytz

from smart_meter_texas.async_api import Auth, Meter

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]

timezone = pytz.timezone("America/Chicago")


async def main():
    async with aiohttp.ClientSession() as websession:
        auth = Auth(websession, username, password)

        print("Authenicating...")
        await auth.authenticate()

        meter = Meter(auth)
        await meter.read_dashboard()
        print(f"Meter: {meter.meter}")
        print(f"ESIID: {meter.esiid}")
        print(f"Address: {meter.address}")

        print("Reading meter (takes about 30s)...")
        await meter.async_read_meter()

        localized_time = meter.reading_datetime.astimezone(timezone)
        print(f"{meter.reading:,.0f} kW @ {localized_time}")


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
