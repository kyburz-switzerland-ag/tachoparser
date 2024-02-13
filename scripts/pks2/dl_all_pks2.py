#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Download root certificate and all member state certs (smart tacho) from
https://dtc.jrc.ec.europa.eu/
"""

from io import BytesIO
from os.path import exists
from time import sleep
from zipfile import ZipFile

import requests
from lxml import html

WWW_PK_URL = "https://dtc.jrc.ec.europa.eu/dtc_public_key_certificates_st.php.html"
PK_BASE_URL = "https://dtc.jrc.ec.europa.eu/"
# old link
# ROOT_PK_ZIP_URL = "https://dtc.jrc.ec.europa.eu/save4Stats_keys.php?name=iot_doc/ERCA Gen2 (1) Root Certificate"
# new link, according to the website
# ROOT_PK_ZIP_URL = "https://dtctest.jrc.cec.eu.int/ERCA_Gen2_Root_Certificate.zip"
# actual new link
ROOT_PK_ZIP_URL = "https://dtc.jrc.ec.europa.eu/ERCA_Gen2_Root_Certificate.zip"
TARGET = "../../internal/pkg/certificates/pks2/"

if __name__ == '__main__':
    # interestingly, there is no checksum for the root ca to be found on the website...
    if not exists(TARGET + "ERCA Gen2 (1) Root Certificate.bin"):
        success = False
        tries = 0
        while not success and tries < 10:
            r = requests.get(ROOT_PK_ZIP_URL)
            if 200 <= r.status_code < 400:
                zipped_content = r.content
                zipfile = ZipFile(BytesIO(zipped_content))
                with zipfile.open("ERCA Gen2 (1) Root Certificate.bin") as z:
                    print("saving ERCA Gen2 (1) Root Certificate.bin")
                    with open(TARGET + "ERCA Gen2 (1) Root Certificate.bin", "wb") as f:
                        f.write(z.read())
                        success = True
            sleep(0.5)

    r = requests.get(WWW_PK_URL)
    tree = html.fromstring(r.content)
    pkas = tree.xpath('//a[@title="Download certificate file"]')
    for pka in pkas:
        key_identifier = pka.xpath('text()')[0]
        if not exists(TARGET + key_identifier + ".bin"):
            link = pka.xpath('@href')[0]
            tries = 0
            success = False
            while not success and tries < 10:
                tries += 1
                r = requests.get(PK_BASE_URL + link)
                if 200 <= r.status_code < 400:
                    c = r.content
                    # although all of the files are exactly 205 bytes long, the specs allow for lengths 204..341
                    if 204 <= len(c) <= 341 and c[0] != 60:  # error page starts with "<"
                        print("saving " + key_identifier + ".bin")
                        with open(TARGET + key_identifier + ".bin", "wb") as f:
                            f.write(c)
                            success = True
                sleep(0.5)
