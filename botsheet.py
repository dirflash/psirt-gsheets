#!/usr/bin/env python
#
# Copyright (c) 2023  Aaron Davis <aarodavi@cisco.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ''AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#
# This script obtains the latest 7, 14, 30 day PSIRTs and stores them in a Google Sheet

#!/usr/bin/python

import os
import configparser
import logging
import logging.handlers as handlers
import sys
import json
import csv
from datetime import date, timedelta
from time import time
import gspread
import requests

logger = logging.getLogger("botsheet")
logger.setLevel(logging.DEBUG)
logHandler = handlers.RotatingFileHandler(
    r".\logs\debug.log", maxBytes=5600, backupCount=2
)
logHandler.setLevel(logging.DEBUG)
logFormatter = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%d %H:%M:%S"
)
stdHandler = logging.StreamHandler(sys.stdout)
logHandler.setFormatter(logFormatter)
stdHandler.setFormatter(logFormatter)
logger.addHandler(stdHandler)

KEY = "CI"
environ = os.getenv(KEY, default="LOCAL")

if environ == "true":
    psirt_grant = "client_credentials"
    psirt_client_id = os.environ["psirt_client_id"]
    psirt_client_secret = os.environ["psirt_client_secret"]
    sa = gspread.service_account("service_account.json")
else:
    config = configparser.ConfigParser()
    config.read("config.ini")
    psirt_grant = config["PSIRT"]["grant_type"]
    psirt_client_id = config["PSIRT"]["client_id"]
    psirt_client_secret = config["PSIRT"]["client_secret"]
    sa = gspread.service_account()
    logger.addHandler(logHandler)

logger.info("Trying to open PSIRTs Google Sheet")
try:
    sh = sa.open("PSIRTs")
except gspread.exceptions.APIError(response) as e:
    print(type(e))
    print(e)
wks = sh.worksheet("Last7")

sh_14 = sa.open("PSIRT-14")
wks_14 = sh_14.worksheet("Last14")

sh_30 = sa.open("PSIRT-30")
wks_30 = sh_30.worksheet("Last30")


def recent_update_7(verify_cve_date):
    """Determines if CVE entry has been updated in last 7 days

    Args:
        verify_cve_date (string): yyyy-mm-ddThh:mm:ss

    Returns:
        bool: True if entry has been updated in last 7 days
    """
    t_index = verify_cve_date.index("T")
    stripped_date = verify_cve_date[:t_index:]
    split_date = tuple(stripped_date.split("-"))
    new_date = date(int(split_date[0]), int(split_date[1]), int(split_date[2]))
    seven_days = date.today() - timedelta(days=7)
    recent = seven_days < new_date
    return recent


def recent_update_14(verify_cve_date):
    """Determines if CVE entry has been updated in last 14 days

    Args:
        verify_cve_date (string): yyyy-mm-ddThh:mm:ss

    Returns:
        bool: True if entry has been updated in last 14 days
    """
    t_index = verify_cve_date.index("T")
    stripped_date = verify_cve_date[:t_index:]
    split_date = tuple(stripped_date.split("-"))
    new_date = date(int(split_date[0]), int(split_date[1]), int(split_date[2]))
    fourteen_days = date.today() - timedelta(days=14)
    recent = fourteen_days < new_date
    return recent


def recent_update_30(verify_cve_date):
    """Determines if CVE entry has been updated in last 30 days

    Args:
        verify_cve_date (string): yyyy-mm-ddThh:mm:ss

    Returns:
        bool: True if entry has been updated in last 30 days
    """
    t_index = verify_cve_date.index("T")
    stripped_date = verify_cve_date[:t_index:]
    split_date = tuple(stripped_date.split("-"))
    new_date = date(int(split_date[0]), int(split_date[1]), int(split_date[2]))
    thirty_days = date.today() - timedelta(days=30)
    recent = thirty_days < new_date
    return recent


def psirt_otoken(
    psirt_f_grant, psirt_f_client_id, psirt_f_client_secret
):  # psirt_grant, psirt_client_id, psirt_client_secret
    """This function creates the OAuth token

    Args:
        grant (str): Token grant type
            (https://raw.githubusercontent.com/api-at-cisco/Images/master/Token_Access.pdf)
        client_id (str): API username
        client_secret (str): API password

    Returns:
        access_token (str): Access token
        token_type (str): Token type ("Bearer")
        token_dies (time): When token expires
    """

    otoken_url = (
        f"https://cloudsso.cisco.com/as/token.oauth2?grant_type={psirt_f_grant}"
        f"&client_id={psirt_f_client_id}&client_secret={psirt_f_client_secret}"
    )

    try:
        otoken_response = requests.request("POST", otoken_url)
        otoken_response.raise_for_status()
    except requests.HTTPError:
        otoken_status = otoken_response.status_code
        if otoken_status == 401:
            logging.error("Invalid API key.")
        elif otoken_status == 404:
            logging.error("Invalid input.")
        elif otoken_status in (429, 443):
            logging.error("API calls per minute exceeded.")
        elif otoken_status == 400:
            logging.error("API bad request.")
        sys.exit(1)

    otoken_data = otoken_response.json()

    otoken_access_token = otoken_data["access_token"]
    otoken_token_type = otoken_data["token_type"]
    otoken_token_expires = otoken_data["expires_in"]

    otoken_token_dies = time() + (otoken_token_expires - 120)

    return (otoken_access_token, otoken_token_type, otoken_token_dies)


# Get OAUTH
otoken_token, otoken_type, otoken_expiry = psirt_otoken(
    psirt_grant, psirt_client_id, psirt_client_secret
)

logger.info("------------------------------------------------------")

# Begin of PSIRT request

TODAY = date.today()
TODAY_STR = str(TODAY)
DELTA = timedelta(days=90)
NINETY_DAYS = TODAY - DELTA
NINETY_DAYS_STR = str(NINETY_DAYS)

psirt_url = (
    f"https://api.cisco.com/security/advisories/all/firstpublished"
    f"?startDate={NINETY_DAYS_STR}&endDate={TODAY_STR}"
)

psirt_token = f"Bearer {otoken_token}"
psirt_headers = {"Authorization": psirt_token}

try:
    psirt_response = requests.request("GET", psirt_url, headers=psirt_headers)
    psirt_response.raise_for_status()
except requests.HTTPError:
    status = psirt_response.status_code
    if status in (401, 403):
        logger.error("Invalid PSIRT API key.")
    elif status == 404:
        logger.error("Invalid PSIRT request input.")
    elif status in (429, 443):
        logger.error("PSIRT API calls per minute exceeded.")
    sys.exit(1)

psirt_json_response = json.loads(psirt_response.text)

# End of PSIRT request

# Convert the PSIRT response to a CSV

cve_entries = psirt_json_response["advisories"]

ENTRY_COUNT = 1
UPDATED_ENTRIES = 1
G_ENTRY_COUNT = 1
G_UPDATED_ENTRIES_7 = 1
G_UPDATED_ENTRIES_14 = 1
G_UPDATED_ENTRIES_30 = 1

header_names = [
    "Advisory_ID",
    "Advisory_Title",
    "CVEs",
    "CVE_Base_Score",
    "Criticality",
    "PSIRT_Version",
    "First_Published",
    "Last_Updated",
    "CVE_Status",
    "Products",
    "Pub_URL",
]

if environ == "LOCAL":
    with open(
        r".\reports\Cisco_PSIRT_" + TODAY_STR + ".csv",
        "w",
        newline="",
        encoding="UTF-8",
    ) as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=";")
        csvwriter.writerow(header_names)

        for entry in cve_entries:
            last_updated = entry["lastUpdated"]
            fresh_update = recent_update_7(last_updated)
            if fresh_update is True:
                UPDATED_ENTRIES += 1
                advisory_id = entry["advisoryId"]
                advisory_title = entry["advisoryTitle"]
                cve_score = entry["cvssBaseScore"]
                criticality = entry["sir"]
                psirt_version = entry["version"]
                first_published = entry["firstPublished"]
                cve_status = entry["status"]
                product_names = entry["productNames"]
                pub_url = entry["publicationUrl"]
                row = [
                    advisory_id,
                    advisory_title,
                    cve_score,
                    criticality,
                    psirt_version,
                    first_published,
                    last_updated,
                    cve_status,
                    product_names,
                    pub_url,
                ]
                csvwriter.writerow(row)

            ENTRY_COUNT += 1

# End of conversion

# Update 7-day Google Sheet

logger.info("Populate 7-day Google Sheet")

wks.clear()

wks.update("A1:K1", [header_names])

for entry in cve_entries:
    last_updated = entry["lastUpdated"]
    fresh_update = recent_update_7(last_updated)
    if fresh_update is True:
        G_UPDATED_ENTRIES_7 += 1
        advisory_id = entry["advisoryId"]
        advisory_title = entry["advisoryTitle"]
        cves_lst = entry["cves"]
        cves = ", ".join(cves_lst)
        cve_score = entry["cvssBaseScore"]
        criticality = entry["sir"]
        psirt_version = entry["version"]
        first_published = entry["firstPublished"]
        cve_status = entry["status"]
        product_names = f'{entry["productNames"]}'
        pub_url = entry["publicationUrl"]
        row = [
            advisory_id,
            advisory_title,
            cves,
            cve_score,
            criticality,
            psirt_version,
            first_published,
            last_updated,
            cve_status,
            product_names,
            pub_url,
        ]
        gsheet_row = f"A{G_UPDATED_ENTRIES_7}:K{G_UPDATED_ENTRIES_7}"
        wks.update(gsheet_row, [row])
    G_ENTRY_COUNT += 1

# Update 14-day Google Sheet
logger.info("Populate 14-day Google Sheet")

wks_14.clear()

wks_14.update("A1:K1", [header_names])

for entry in cve_entries:
    last_updated = entry["lastUpdated"]
    fresh_update = recent_update_14(last_updated)
    if fresh_update is True:
        G_UPDATED_ENTRIES_14 += 1
        advisory_id = entry["advisoryId"]
        advisory_title = entry["advisoryTitle"]
        cves_lst = entry["cves"]
        cves = ", ".join(cves_lst)
        cve_score = entry["cvssBaseScore"]
        criticality = entry["sir"]
        psirt_version = entry["version"]
        first_published = entry["firstPublished"]
        cve_status = entry["status"]
        product_names = f'{entry["productNames"]}'
        pub_url = entry["publicationUrl"]
        row = [
            advisory_id,
            advisory_title,
            cves,
            cve_score,
            criticality,
            psirt_version,
            first_published,
            last_updated,
            cve_status,
            product_names,
            pub_url,
        ]
        gsheet_row = f"A{G_UPDATED_ENTRIES_14}:K{G_UPDATED_ENTRIES_14}"
        wks_14.update(gsheet_row, [row])

# Update 30-day Google Sheet
logger.info("Populate 30-day Google Sheet")

wks_30.clear()

wks_30.update("A1:K1", [header_names])

for entry in cve_entries:
    last_updated = entry["lastUpdated"]
    fresh_update = recent_update_30(last_updated)
    if fresh_update is True:
        G_UPDATED_ENTRIES_30 += 1
        advisory_id = entry["advisoryId"]
        advisory_title = entry["advisoryTitle"]
        cves_lst = entry["cves"]
        cves = ", ".join(cves_lst)
        cve_score = entry["cvssBaseScore"]
        criticality = entry["sir"]
        psirt_version = entry["version"]
        first_published = entry["firstPublished"]
        cve_status = entry["status"]
        product_names = f'{entry["productNames"]}'
        pub_url = entry["publicationUrl"]
        row = [
            advisory_id,
            advisory_title,
            cves,
            cve_score,
            criticality,
            psirt_version,
            first_published,
            last_updated,
            cve_status,
            product_names,
            pub_url,
        ]
        gsheet_row = f"A{G_UPDATED_ENTRIES_30}:K{G_UPDATED_ENTRIES_30}"
        wks_30.update(gsheet_row, [row])

TTL_CNT = G_ENTRY_COUNT - 1
SVN_CNT = G_UPDATED_ENTRIES_7 - 1
FTN_CNT = G_UPDATED_ENTRIES_14 - 1
TTY_CNT = G_UPDATED_ENTRIES_30 - 1

logger.info("Total number of CVE entries: %s", TTL_CNT)
logger.info("Number of updated CVE entries in last 7-days: %s", SVN_CNT)
logger.info("Number of updated CVE entries in last 14-days: %s", FTN_CNT)
logger.info("Number of updated CVE entries in last 30-days: %s", TTY_CNT)

if SVN_CNT == 0:
    wks.update("A2", "No updated CVEs in this time-frame")

if FTN_CNT == 0:
    wks_14.update("A2", "No updated CVEs in this time-frame")


if TTY_CNT == 0:
    wks_30.update("A2", "No updated CVEs in this time-frame")
