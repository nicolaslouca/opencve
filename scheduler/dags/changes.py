import importlib
import json
import logging
import uuid
import arrow

import arrow
import pendulum
from airflow.decorators import dag, task
from airflow.providers.postgres.operators.postgres import PostgresOperator
from psycopg2.extras import Json
from airflow.providers.postgres.hooks.postgres import PostgresHook
from constants import PROCEDURES

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
    def __init__(self, commit, diff):
        self.commit = commit
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
    def cve_name(self):
        if not self.is_cve:
            return None
        # Example: nvd/2023/CVE-2023-28640.json
        return self.path.split("/")[2].split(".")[0]

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
            self._left = (
                json.loads(self.diff.a_blob.data_stream.read().decode("utf-8"))
                if self.diff.a_blob
                else None
            )
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

        # Update the source
        source.upsert(self.right)

        # Create the change and its events
        events = source.get_events(self.left, self.right)
        if events:
            parameters = {
                "cve": self.cve_name,
                "path": self.path,
                "commit": str(self.commit),
                "events": Json(events),
                "created": arrow.get(self.commit.authored_date).datetime.isoformat(),
                "updated": arrow.get(self.commit.authored_date).datetime.isoformat(),
            }

            # Insert in the database
            hook = PostgresHook(postgres_conn_id="opencve_postgres")
            hook.run(sql=PROCEDURES.get("events"), parameters=parameters)
