import json
import logging
import re
import time
from datetime import date, datetime
from pathlib import Path

import arrow
import requests
from airflow.models.variable import Variable
from bs4 import BeautifulSoup, SoupStrainer
from psycopg2.extras import Json
from sources import BaseSource

logger = logging.getLogger("airflow.task")


class DsaSource(BaseSource):
    name = "dsa"
    type = "advisory"

    CURRENT_YEAR = date.today().year
    DSA_FIRST_YEAR = 2000
    BASE_URL = "https://www.debian.org/security"
    STRAINER = SoupStrainer("div", id="content")

    def parse_dsa_page(self, year, dsa):
        link = dsa.get("href")[2:]
        dsa_id = dsa.text.split()[0]

        response = requests.get(f"{self.BASE_URL}/{year}/{link}")
        soup = BeautifulSoup(
            response.content, parse_only=self.STRAINER, features="html.parser"
        )

        # Date format is "30 Dec 2021"
        creation_date = (
            arrow.get(
                soup.find("dt", text="Date Reported:").find_next_sibling("dd").text,
                "DD MMM YYYY",
            )
            .to("utc")
            .format()
        )

        # Populate the advisory object
        dsa_data = {
            "id": dsa_id,
            "title": soup.h2.text.split("--")[0].strip(),
            "text": soup.find("dt", text="More information:")
            .find_next_sibling("dd")
            .text,
            "vulnerable": soup.find("dt", text="Vulnerable:")
            .find_next_sibling("dd")
            .text,
            "packages": [
                a.text
                for a in soup.find("dt", text="Affected Packages:")
                .find_next_sibling("dd")
                .find_all("a")
            ],
            "fixed_in": None,
            "created_at": creation_date,
            "updated_at": creation_date,
            "cves": [],  # TODO
        }

        # The "Fixed in" section is not always available
        fixed_in = soup.find("dt", text="Fixed in:")
        if fixed_in:
            dsa_data["fixed_in"] = fixed_in.find_next_sibling("dd").text

        return dsa_data

    def parse_year_page(self, year):
        url = f"{self.BASE_URL}/{year}"
        logger.info(f"Downloading and parsing %s", url)

        # Ensure the year folder is created
        path = Path(self.path) / str(year)
        path.mkdir(parents=True, exist_ok=True)

        response = requests.get(url)
        soup = BeautifulSoup(
            response.content, parse_only=self.STRAINER, features="html.parser"
        )

        dsa_list = [dsa for dsa in soup.find_all("a", text=re.compile("DSA"))]
        logger.info(f"Parsing {len(dsa_list)} DSA for {year}")

        for dsa_link in dsa_list:
            dsa = self.parse_dsa_page(year, dsa_link)

            with open(Path(self.path) / str(year) / f"{dsa['id']}.json", "w") as f:
                json.dump(dsa, f, indent=2, sort_keys=True)

            # Reduce the load on Debian website
            time.sleep(1)

    def parse_all_years(self):
        for year in range(self.DSA_FIRST_YEAR, self.CURRENT_YEAR + 1):
            self.parse_year_page(year)
        Variable.set("source_debian_initialized", datetime.utcnow())

    def run(self):
        if not Variable.get("source_debian_initialized", default_var=False):
            self.parse_all_years()
        else:
            self.parse_year_page(self.CURRENT_YEAR)

    @classmethod
    def parse_obj(cls, path, data):
        return {
            "created": arrow.get(data["created_at"]).datetime.isoformat(),
            "updated": arrow.get(data["updated_at"]).datetime.isoformat(),
            "key": data["id"],
            "title": data["title"],
            "text": data["text"],
            "source": cls.name,
            "link": "TO COMPLETE",
            "extras": Json(
                {"vulnerable": data["vulnerable"], "packages": data["packages"]}
            ),
        }

    @classmethod
    def update(cls, path, old, data):
        print("UPDATING DSA...")
        return {}
