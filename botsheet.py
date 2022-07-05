import os
import configparser
import logging
import sys
import json
import csv
from datetime import date, timedelta
from time import time
import gspread
import requests

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(r".\logs\debug.log"),
        logging.StreamHandler(sys.stdout),
    ],
)

KEY = "CI"
environ = os.getenv(KEY, default="LOCAL")

if environ == "true":
    psirt_grant = "client_credentials"
    psirt_client_id = os.environ["psirt_client_id"]
    psirt_client_secret = os.environ["psirt_client_secret"]
    # gsheets_auth = os.environ["gsheets_auth"]
    sa = gspread.service_account("service_account.json")
else:
    config = configparser.ConfigParser()
    config.read("config.ini")
    psirt_grant = config["PSIRT"]["grant_type"]
    psirt_client_id = config["PSIRT"]["client_id"]
    psirt_client_secret = config["PSIRT"]["client_secret"]
    sa = gspread.service_account()

sh = sa.open("PSIRTs")

wks = sh.worksheet("Last7")


def recent_update(verify_cve_date):
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

logging.info("------------------------------------------------------")

# Begin of PSIRT request

TODAY = date.today()
TODAY_STR = str(TODAY)
DELTA = timedelta(days=90)
NINTY_DAYS = TODAY - DELTA
NINTY_DAYS_STR = str(NINTY_DAYS)

psirt_url = (
    f"https://api.cisco.com/security/advisories/all/firstpublished"
    f"?startDate={NINTY_DAYS_STR}&endDate={TODAY_STR}"
)

psirt_token = f"Bearer {otoken_token}"
psirt_headers = {"Authorization": psirt_token}

try:
    psirt_response = requests.request("GET", psirt_url, headers=psirt_headers)
    psirt_response.raise_for_status()
except requests.HTTPError:
    status = psirt_response.status_code
    if status in (401, 403):
        logging.error("Invalid PSIRT API key.")
    elif status == 404:
        logging.error("Invalid PSIRT request input.")
    elif status in (429, 443):
        logging.error("PSIRT API calls per minute exceeded.")
    sys.exit(1)

psirt_json_response = json.loads(psirt_response.text)

# End of PSIRT request

# Convert the PSIRT response to a CSV

cve_entries = psirt_json_response["advisories"]

ENTRY_COUNT = 1
UPDATED_ENTRIES = 0

header_names = [
    "Advisory_ID",
    "Advisory_Title",
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
            fresh_update = recent_update(last_updated)
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

    logging.info("Total number of CVE entries: %s", ENTRY_COUNT)
    print(f"Total number of CVE entries: {ENTRY_COUNT}")
    logging.info("Number of updated CVE entries: %s", UPDATED_ENTRIES)
    print(f"Total number of CVE entries: {UPDATED_ENTRIES}")

# End of conversion

# Update Google Sheet
wks.clear()

wks.update("A1:J1", [header_names])

for entry in cve_entries:
    last_updated = entry["lastUpdated"]
    fresh_update = recent_update(last_updated)
    if fresh_update is True:
        UPDATED_ENTRIES += 1
        advisory_id = entry["advisoryId"]
        advisory_title = entry["advisoryTitle"]
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
            cve_score,
            criticality,
            psirt_version,
            first_published,
            last_updated,
            cve_status,
            product_names,
            pub_url,
        ]
        gsheet_row = f"A{UPDATED_ENTRIES}:J{UPDATED_ENTRIES}"
        wks.update(gsheet_row, [row])
