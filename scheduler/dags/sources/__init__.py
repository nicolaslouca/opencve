import logging
import os
from pathlib import Path
from airflow.providers.postgres.hooks.postgres import PostgresHook

logger = logging.getLogger("airflow.task")


# See https://stackoverflow.com/a/73983599/663949
os.environ["no_proxy"] = "*"


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
    def sql(cls, query, parameters):
        hook = PostgresHook(postgres_conn_id="opencve_postgres")
        hook.run(sql=query, parameters=parameters)

    @classmethod
    def upsert(cls, data):
        raise NotImplementedError

    @classmethod
    def get_events(cls, old, new):
        return []
