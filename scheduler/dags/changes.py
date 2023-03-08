import json
import logging
import uuid
import importlib

import pendulum
import arrow
from deepdiff import DeepDiff
from airflow.decorators import dag, task
from airflow.providers.postgres.operators.postgres import PostgresOperator


"""@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def changes():
    select_last_change = PostgresOperator(
        task_id="select_last_change",
        postgres_conn_id="opencve_postgres",
        sql="sql/import_cves.sql",
    )


changes()"""

logger = logging.getLogger(__name__)


class Handlers:
    def __init__(self, diff):
        self.diff = diff
        self._source = None
        self._left = None
        self._right = None

    @property
    def is_new(self):
        return self.diff.change_type == "A"

    @property
    def is_cve(self):
        return self.source in ["nvd"]

    @property
    def source(self):
        if not self._source:
            return self.diff.b_path.split("/")[0]
        return self._source

    @property
    def left(self):
        if not self._left:
            self._left = json.loads(self.diff.a_blob.data_stream.read().decode('utf-8'))
        return self._left

    @property
    def right(self):
        if not self._right:
            self._right = json.loads(self.diff.b_blob.data_stream.read().decode('utf-8'))
        return self._right

    def parse_cve(self):
        print(self.right)

        cvss2 = (
            self.right["metrics"]["cvssMetricV2"][0]["cvssData"]["baseScore"]
            if "cvssMetricV2" in self.right["metrics"]
            else None
        )

        cvss3 = (
            self.right["metrics"]["cvssMetricV3"][0]["cvssData"]["baseScore"]
            if "cvssMetricV3" in self.right["metrics"]
            else None
        )

        return [
            str(uuid.uuid4()),
            self.right["published"],
            self.right["lastModified"],
            self.right["id"],
            [],
            [],
            self.right["descriptions"][0]["value"],
            cvss2,
            cvss3
        ]

    def parse_advisory(self):
        return []

    def a(self):
        # TODO: use self.source to dynamically call the right method
        # OR BETTER: each source file (ie ./sources/dsa.py::DsaSource) implements it as classmethod
        # self.parse_dsa(), self.parse_jvn(), etc...
        if self.is_cve:
            return self.parse_cve()
        return self.parse_advisory()

    def m(self):
        deepdiff = DeepDiff(self.left, self.right)
        logger.info("je vais faire une MODIF")
        return []

    def execute(self):
        logger.info(f"Analysing {self.diff.b_path} ({self.diff.change_type})")

        module = importlib.import_module(f'sources.{self.source}')
        source = getattr(module, f'{self.source.capitalize()}Source')

        if not self.is_new:
            return source.update(self.left, self.right)

        return source.create(self.right)


    """
    INSERT INTO opencve_cves (id, created_at, updated_at, cve_id, json, vendors, cwes, summary, cvss2, cvss3)
    VALUES(uuid_generate_v4(), NOW(), NOW(), 'CVE-2023-1234', '{}', '{}', '{}', 'Lorem ipsum', 10, 10)
    ON CONFLICT (cve_id) DO
    UPDATE SET updated_at = NOW(), json = EXCLUDED.json || '{"source": "/path/to/source.json"}'
    """
