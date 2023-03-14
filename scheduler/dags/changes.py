import importlib
import json
import logging
import uuid

import arrow
import pendulum
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
        self._path = None
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
            self._source = self.diff.b_path.split("/")[0]
        return self._source

    @property
    def path(self):
        if not self._path:
            self._path = self.diff.b_path
        return self._path

    @property
    def left(self):
        if not self._left:
            self._left = json.loads(self.diff.a_blob.data_stream.read().decode("utf-8"))
        return self._left

    @property
    def right(self):
        if not self._right:
            self._right = json.loads(
                self.diff.b_blob.data_stream.read().decode("utf-8")
            )
        return self._right

    def execute(self):
        logger.info(f"Analysing {self.diff.b_path} ({self.diff.change_type})")

        module = importlib.import_module(f"sources.{self.source}")
        source = getattr(module, f"{self.source.capitalize()}Source")

        if not self.is_new:
            return source.update(self.path, self.left, self.right)

        return source.upsert(self.path, self.right)
