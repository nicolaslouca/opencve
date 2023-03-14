import logging
import os
from pathlib import Path
from airflow.providers.postgres.hooks.postgres import PostgresHook

logger = logging.getLogger("airflow.task")


# See https://stackoverflow.com/a/73983599/663949
os.environ["no_proxy"] = "*"

PROCEDURES = {
    "cve": "CALL create_cve(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(cvss2)s, %(cvss3)s, %(vendors)s, %(cwes)s, %(source)s);",
    "advisory": "CALL create_advisory(%(created)s, %(updated)s, %(key)s, %(title)s, %(text)s, %(source)s, %(link)s, %(extras)s);"
}


class BaseSource:
    name: str = None
    path: Path = None
    type: str = None

    def __init__(self, path: Path):
        self.path = path
        self.init_path()

        logger.info(f"Updating {self.name} source")

    def init_path(self):
        self.path.mkdir(parents=True, exist_ok=True)

    def run(self):
        raise NotImplementedError

    @classmethod
    def upsert(cls, path, data):
        params = cls.parse_obj(path, data)
        hook = PostgresHook(postgres_conn_id="opencve_postgres")
        hook.run(
            sql=PROCEDURES.get(cls.type),
            parameters=params,
        )

    @classmethod
    def parse_obj(cls, path, data):
        raise NotImplementedError

    @classmethod
    def update(cls, path, old, data):
        raise NotImplementedError
