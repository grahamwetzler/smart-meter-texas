import re
import socket
import ssl
import urllib

import certifi
import OpenSSL.crypto as crypto

from smart_meter_texas.const import BASE_HOSTNAME


def get_ssl_context():
    caiKey = "CA Issuers - URI:"
    re_issuers_uri = re.compile(r"(https?://+[\w\d:#@%/;$()~_?\+-=\\\.&]*)", re.UNICODE)

    ca_issuers_uri = None
    context = ssl.create_default_context(capath=certifi.where())
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
                auth_info_access = str(ext)
                cai_indx = auth_info_access.find(caiKey)
                if cai_indx > -1:
                    cai_value = auth_info_access[cai_indx:]
                    ca_issuers_uri = re_issuers_uri.findall(cai_value)[0]

    if ca_issuers_uri != None:
        with urllib.request.urlopen(ca_issuers_uri) as cert_req:
            cert_data = cert_req.read()
            context.load_verify_locations(cafile=certifi.where(), cadata=cert_data)

    # Re-enable checking
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= (
        ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_SSLv3 | ssl.OP_NO_SSLv2
    )

    return context
