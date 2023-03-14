import json
import logging
import os
from pathlib import Path

import requests
from airflow.models.variable import Variable
from lxml import etree
from pydantic import ValidationError
from sources import BaseSource

REDHAT_CVES_URL = "https://access.redhat.com/labs/securitydataapi/cve.json?page={page}"
REDHAT_CVE_URL = "https://access.redhat.com/labs/securitydataapi/cve/{cve_id}.json"


logger = logging.getLogger("airflow.task")


# class RedhatSource(BaseSource):
class RedhatSource:
    name = "redhat"
    type = "advisory"

    @staticmethod
    def download_file(url):
        resp = requests.get(url)
        return resp.json()

    def run(self):
        if not Variable.get("source_redhat_initialized", default_var=False):
            page = 1
            while True:
                url = REDHAT_CVES_URL.format(page=page)

                logger.info(f"Downloading and parsing %s", url)
                cve_list = self.download_file(url)
                print(len(cve_list))
                print(cve_list[0])
                page += 1
                break

    @classmethod
    def parse_object(cls, path, data):
        raise NotImplementedError

    @classmethod
    def update(cls, path, old, data):
        raise NotImplementedError
