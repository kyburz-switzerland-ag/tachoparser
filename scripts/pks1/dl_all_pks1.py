#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Download root certificate and all member state certs (digital tacho) from
https://dtc.jrc.ec.europa.eu/
"""

from io import BytesIO
from os.path import exists
from time import sleep
from zipfile import ZipFile

import requests
from lxml import html

WWW_PK_URL = "https://dtc.jrc.ec.europa.eu/dtc_public_key_certificates_dt.php.html"
PK_BASE_URL = "https://dtc.jrc.ec.europa.eu/"
ROOT_PK_ZIP_URL = "https://dtc.jrc.ec.europa.eu/erca_of_doc/EC_PK.zip"
TARGET = "../../internal/pkg/certificates/pks1/"

if __name__ == '__main__':
    # interestingly, there is no checksum for the root ca to be found on the website...
    if not exists(TARGET + "EC_PK.bin"):
        success = False
        tries = 0
        while not success and tries < 10:
            tries += 1
            r = requests.get(ROOT_PK_ZIP_URL)
            if 200 <= r.status_code < 400:
                zipped_content = r.content
                zipfile = ZipFile(BytesIO(zipped_content))
                with zipfile.open("EC_PK.bin") as z:
                    print("saving EC_PK.bin")
                    with open(TARGET + "EC_PK.bin", "wb") as f:
                        f.write(z.read())
                        success = True
            sleep(0.5)

    # ...that is why we do not check the checksum of the member state certificates
    r = requests.get(WWW_PK_URL)
    tree = html.fromstring(r.content)
    pkas = tree.xpath('//a[@title="Download certificate file"]')
    for pka in pkas:
        key_identifier = pka.xpath('text()')[0]
        if not exists(TARGET + key_identifier + ".bin"):
            link = pka.xpath('@href')[0]
            success = False
            tries = 0
            while not success and tries < 10:
                tries += 1
                r = requests.get(PK_BASE_URL + link)
                if 200 <= r.status_code < 400:
                    c = r.content
                    if len(c) == 194:
                        print("saving " + key_identifier + ".bin")
                        with open(TARGET + key_identifier + ".bin", "wb") as f:
                            f.write(c)
                            success = True
                sleep(0.5)
