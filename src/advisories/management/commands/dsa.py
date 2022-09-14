import re

import arrow
import requests
from bs4 import BeautifulSoup, SoupStrainer

from core.management.commands import BaseCommand
from advisories.models import Advisory


class Command(BaseCommand):
    CURRENT_YEAR = arrow.now().year
    CVE_FIRST_YEAR = 2002
    BASE_URL = "https://www.debian.org/security"
    STRAINER = SoupStrainer("div", id="content")

    help = "Import DSA advisories"

    def parse_dsa_page(self, year, dsa):
        response = requests.get(f"{self.BASE_URL}/{year}/{dsa.lower()}")

        soup = BeautifulSoup(
            response.content, parse_only=self.STRAINER, features="html.parser"
        )

        # Date format is "30 Dec 2021"
        creation_date = arrow.get(
            soup.find("dt", text="Date Reported:").find_next_sibling("dd").text,
            "DD MMM YYYY",
        ).datetime

        # Populate the advisory object
        advisory = Advisory(
            name=dsa,
            text=soup.find("dt", text="More information:").find_next_sibling("dd").text,
            source="dsa",
            created_at=creation_date,
            updated_at=creation_date,
            extras={
                "title": soup.h2.text.split("--")[0].strip(),
                "vulnerable": soup.find("dt", text="Vulnerable:")
                .find_next_sibling("dd")
                .text,
                "packages": [
                    a.text
                    for a in soup.find("dt", text="Affected Packages:")
                    .find_next_sibling("dd")
                    .find_all("a")
                ],
            },
        )

        # The "Fixed in" section is not always available
        fixed_in = soup.find("dt", text="Fixed in:")
        if fixed_in:
            advisory.extras["fixed_in"] = fixed_in.find_next_sibling("dd").text

        return advisory

    def parse_dsa_list(self, year):
        advisories = []

        url = f"{self.BASE_URL}/{year}"
        with self.timed_operation(f"Downloading and parsing {url}..."):
            response = requests.get(url)
            soup = BeautifulSoup(
                response.content, parse_only=self.STRAINER, features="html.parser"
            )

        with self.timed_operation(f"Extracting objects..."):
            for link in soup.find_all("a", text=re.compile("DSA")):
                advisories.append(self.parse_dsa_page(year, link.text.split()[0]))

        return advisories

    def handle(self, *args, **kwargs):
        for year in range(2021, 2023):
            self.info(self.style.MIGRATE_HEADING(f"Importing DSA for {year}:"))

            # Extract the list of DSA for this year and insert it in DB
            objects = self.parse_dsa_list(year)

            with self.timed_operation(f"Inserting advisories..."):
                Advisory.objects.bulk_create(objects)

            self.info(
                f"  {self.style.MIGRATE_LABEL(len(objects))} DSA advisories imported"
            )
