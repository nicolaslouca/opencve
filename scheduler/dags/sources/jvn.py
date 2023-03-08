import json
import logging
import os
from pathlib import Path
from typing import List, Optional

import requests
from lxml import etree
from pydantic import BaseModel, HttpUrl, ValidationError
from sources import BaseSource

JVN_RDF_URL = "https://jvndb.jvn.jp/en/rss/jvndb.rdf"

logger = logging.getLogger("airflow.task")


class Reference(BaseModel):
    id: str
    source: Optional[str]
    text: str


class Cpe(BaseModel):
    version: str
    vendor: str
    product: str
    uri: str


class Cvss(BaseModel):
    version: str
    type: str
    score: Optional[float]
    severity: Optional[str]
    vector: Optional[str]


class Item(BaseModel):
    title: str
    description: str
    link: HttpUrl
    identifier: str  # to change with a regex
    date: str
    issued: str
    modified: str
    references: Optional[List[Reference]]
    cpe: Optional[List[Cpe]]
    cvss: Optional[List[Cvss]]


class JvnSource(BaseSource):
    name = "jvn"

    @staticmethod
    def reformat_references(references):
        return [
            {
                "source": reference.get("source"),
                "id": reference.get("id"),
                "text": reference.text,
            }
            for reference in references
        ]

    @staticmethod
    def reformat_cpes(cpes):
        return [
            {
                "version": cpe.get("version"),
                "vendor": cpe.get("vendor"),
                "product": cpe.get("product"),
                "uri": cpe.text,
            }
            for cpe in cpes
        ]

    @staticmethod
    def reformat_cvss(cvss):
        return [
            {
                "version": c.get("version"),
                "score": c.get("score"),
                "type": c.get("type"),
                "severity": c.get("Severity"),
                "vector": c.get("vector"),
            }
            for c in cvss
        ]

    @staticmethod
    def download_file():
        resp = requests.get(JVN_RDF_URL, stream=True)
        return resp.raw

    def run(self):
        self.download_file()
        tree = etree.parse(self.download_file())
        root = tree.getroot()

        for child in root:
            child.tag = etree.QName(child).localname

            # Ignore the channel tag
            if child.tag == "channel":
                continue

            # References, CPE & CVSS are multiple
            item_data = {"references": [], "cpe": [], "cvss": []}

            # Loop on all items
            for subchild in child:
                subchild.tag = etree.QName(subchild).localname

                if subchild.tag not in ("references", "cpe", "cvss"):
                    item_data[subchild.tag] = subchild.text
                else:
                    item_data[subchild.tag].append(subchild)

            item_data["references"] = self.reformat_references(item_data["references"])
            item_data["cpe"] = self.reformat_cpes(item_data["cpe"])
            item_data["cvss"] = self.reformat_cvss(item_data["cvss"])

            # Validate the JVN object
            try:
                item = Item(**item_data)
            except ValidationError as e:
                logger.error(f"Validation Error")
                logger.error(f"Data was: {item_data}")
                raise e
            else:
                with open(Path(self.path) / f"{item.identifier}.json", "w") as f:
                    json.dump(item_data, f, indent=2, sort_keys=True)

    @classmethod
    def create(cls, data):
        print("Je vais créer une nouvelle entrée JVN...")
        return {}

    @classmethod
    def update(cls, old, data):
        print("Je vais modifier une JVN existante...")
        return {}
