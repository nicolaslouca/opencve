import re

import arrow
import requests
from bs4 import BeautifulSoup, SoupStrainer

from core.management.commands import BaseCommand
from advisories.models import Advisory


class Command(BaseCommand):
    CURRENT_YEAR = arrow.now().year
    CVE_FIRST_YEAR = 2002
    ALL_URL = "http://jvn.jp/en/report/all.html"
    STRAINER = SoupStrainer("div", id="content")

    help = "Import JVN advisories"

    def handle(self, *args, **kwargs):
        url = f"{self.ALL_URL}"
        advisories = []

        self.info(self.style.MIGRATE_HEADING("Importing JVN data..."))
        with self.timed_operation(f"Downloading and parsing {url}..."):
            response = requests.get(url)
            soup = BeautifulSoup(
                response.content, features="html.parser"
            )
            dls = soup.find_all("dl")
            for dl in dls:
                dt_text = dl.find("dt").text.strip()
                dd = dl.find("dd")
                date = arrow.get(dt_text.split()[0], "YYYY/MM/DD").datetime

                link = dd.find("a")["href"]
                advisories.append(Advisory(
                    source="jvn",
                    key=dt_text.split()[1].split(":")[0],
                    title=dd.text,
                    text="to complete",
                    created_at=date,
                    updated_at=date,
                    extras={}
                ))

        Advisory.objects.bulk_create(advisories)
        self.info(
            f"  {self.style.MIGRATE_LABEL(len(advisories))} JVN advisories imported"
        )
