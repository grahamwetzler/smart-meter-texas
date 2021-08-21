"""Example to show how to fetch all meters associated with a user's account."""

import asyncio
import logging
import os
import sys
import ssl
import socket
import aiohttp
import OpenSSL.crypto as crypto
import certifi
import re
import urllib

from smart_meter_texas import Account, Client

from smart_meter_texas.const import (
    BASE_HOSTNAME
)

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

username = os.environ["SMTUSER"]
password = os.environ["SMTPW"]

async def main():
    caiKey = 'CA Issuers - URI:'
    reIssuersURI = re.compile(r"(https?://+[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.UNICODE)

    caIssuersURI = None
    context =  ssl.create_default_context(capath=certifi.where())
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with context.wrap_socket(socket.socket(), server_hostname=BASE_HOSTNAME) as s:
        s.connect((BASE_HOSTNAME, 443))
        cert_bin = s.getpeercert(True)
        x509 = crypto.load_certificate(crypto.FILETYPE_ASN1, cert_bin)
        for idx in range(x509.get_extension_count()):
            ext = x509.get_extension(idx)
            short_name = ext.get_short_name()
            if short_name == b"authorityInfoAccess":
                authorityInfoAccess = str(ext)

                caiIndx = authorityInfoAccess.find(caiKey)
                if (caiIndx > -1):
                    caiValue = authorityInfoAccess[caiIndx:]
                    caIssuersURI = reIssuersURI.findall(caiValue)[0]

    if (caIssuersURI != None):
        with urllib.request.urlopen(caIssuersURI) as certReq:
            certData = certReq.read()
            context.load_verify_locations(cafile=certifi.where(), cadata = certData)


    # Re-enable checking
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2

    async with aiohttp.ClientSession() as websession:
        account = Account(username, password)
        client = Client(websession, account, sslcontext=context)
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
