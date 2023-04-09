import json
import logging
import time
from datetime import date, datetime, timezone
from pathlib import Path

import arrow
import requests
from airflow.models.variable import Variable
from airflow.providers.postgres.hooks.postgres import PostgresHook
from deepdiff import DeepDiff
from psycopg2.extras import Json
from pydantic import BaseModel, ValidationError
from sources import BaseSource
from sources.nvd.events import NvdEvents
from constants import PROCEDURES
from utils import vendors_conf_to_flat, weaknesses_to_flat

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_FIRST_YEAR = 1999
CURRENT_YEAR = date.today().year


logger = logging.getLogger("airflow.task")


class Vulnerability(BaseModel):
    id: str


class NvdSource(BaseSource):
    name = "nvd"
    type = "cve"

    def create_years_dirs(self):
        for year in range(CVE_FIRST_YEAR, CURRENT_YEAR + 1):
            path = Path(self.path) / str(year)
            path.mkdir(parents=True, exist_ok=True)

    def iterate(self, url_template):
        start_index = 0
        total_results = 0

        while start_index <= total_results:
            url = url_template.format(idx=start_index)
            logger.info("Fetching %s", url)
            resp = requests.get(url)
            data = resp.json()
            total_results = data.get("totalResults")

            for vulnerability in data.get("vulnerabilities"):
                cve_data = vulnerability.get("cve")
                try:
                    cve = Vulnerability(**cve_data)
                except ValidationError as e:
                    print(e)
                else:
                    # Create the file in its year folder
                    path = Path(self.path) / cve.id.split("-")[1]
                    with open(path / f"{cve.id}.json", "w") as f:
                        json.dump(cve_data, f, indent=2, sort_keys=True)

            # NVD requirement is 2000 CVE per page
            # and 6 seconds between requests.
            start_index += 2000
            time.sleep(6)

        Variable.set("source_nvd_initialized", datetime.utcnow())

    @staticmethod
    def parse_last_changes():
        hook = PostgresHook(postgres_conn_id="opencve_postgres")
        cve_id, last_mod_date = hook.get_first(
            sql="SELECT cve_id, updated_at FROM opencve_cves ORDER BY created_at DESC LIMIT 1;"
        )
        logger.info("Parsing last changes since %s (at %s)", cve_id, last_mod_date)

        # We use UTC start & end dates
        start = last_mod_date.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
        return NVD_API_URL + f"?lastModStartDate={start}Z&lastModEndDate={end}Z"

    def run(self):
        self.create_years_dirs()

        if not Variable.get("source_nvd_initialized", default_var=False):
            logger.info(
                "Parsing all years (from %s to %s)", CVE_FIRST_YEAR, CURRENT_YEAR
            )
            url = NVD_API_URL + "?startIndex={idx}"
        else:
            url = self.parse_last_changes() + "&startIndex={idx}"

        self.iterate(url)

    @classmethod
    def upsert(cls, data):
        cve_id = data["id"]
        year = cve_id.split("-")[1]
        source = {cls.name: f"{cls.name}/{year}/{cve_id}.json"}

        cvss2 = (
            data["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            if "cvssMetricV2" in data["metrics"]
            else None
        )

        cvss3 = (
            data["metrics"]["cvssMetricV3"][0]["cvssData"]["baseScore"]
            if "cvssMetricV3" in data["metrics"]
            else None
        )

        cls.sql(
            query=PROCEDURES.get("nvd"),
            parameters={
                "cve": data["id"],
                "created": arrow.get(data["published"]).datetime.isoformat(),
                "updated": arrow.get(data["lastModified"]).datetime.isoformat(),
                "summary": data["descriptions"][0]["value"],
                "cvss2": cvss2,
                "cvss3": cvss3,
                "vendors": Json(vendors_conf_to_flat(data.get("configurations"))),
                "cwes": Json(weaknesses_to_flat(data.get("weaknesses"))),
                "source": Json(source),
            },
        )

    @classmethod
    def get_events(cls, old, new):
        events = []

        # New CVE
        if not old:
            return [{"type": "new_cve", "details": {}}]

        # Check other events
        events_cls = NvdEvents.__subclasses__()
        for event_cls in events_cls:
            e = event_cls(old, new)
            event = e.execute()

            if event:
                events.append(event)

        return events
