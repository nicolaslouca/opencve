import re
import time

from bs4 import BeautifulSoup, SoupStrainer
import requests

BASE_URL = "https://www.debian.org/security"
STRAINER = SoupStrainer("div", id="content")


def parse_dsa_list(year):
    time.sleep(0.5)
    response = requests.get(f"{BASE_URL}/{year}")

    soup = BeautifulSoup(response.content, parse_only=STRAINER, features="html.parser")

    for link in soup.find_all("a", text=re.compile("DSA")):
        dsa = link.text.split()[0]
        parse_dsa_page(year, dsa)


def parse_dsa_page(year, dsa):
    time.sleep(0.5)
    response = requests.get(f"{BASE_URL}/{year}/{dsa}")

    soup = BeautifulSoup(response.content, parse_only=STRAINER, features="html.parser")

    obj = {
        "id": dsa,
        "title": soup.h2.text.split("--")[0].strip(),
        "date": soup.find("dt", text="Date Reported:").find_next_sibling("dd").text,
        "vulnerable": soup.find("dt", text="Vulnerable:").find_next_sibling("dd").text,
        "packages": [
            a.text
            for a in soup.find("dt", text="Affected Packages:")
            .find_next_sibling("dd")
            .find_all("a")
        ],
        "more_information": soup.find("dt", text="More information:")
        .find_next_sibling("dd")
        .text,
    }

    # The "Fixed in" section is not always available
    fixed_in = soup.find("dt", text="Fixed in:")
    if fixed_in:
        obj["fixed_in"] = fixed_in.find_next_sibling("dd").text

    return obj


# for year in range(2021, 2023):
#    parse_dsa_list(year)


parse_dsa_page(2022, "dsa-5035")
parse_dsa_page(2001, "dsa-037")
