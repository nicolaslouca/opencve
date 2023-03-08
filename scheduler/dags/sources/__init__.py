import logging
import os
from pathlib import Path

logger = logging.getLogger("airflow.task")


# See https://stackoverflow.com/a/73983599/663949
os.environ["no_proxy"] = "*"


class BaseSource:
    name: str = None
    path: Path = None

    def __init__(self, path: Path):
        self.path = path
        self.init_path()

        logger.info(f"Updating {self.name} source")

    def init_path(self):
        self.path.mkdir(parents=True, exist_ok=True)

    def run(self):
        raise NotImplementedError

    @classmethod
    def create(cls, data):
        raise NotImplementedError

    @classmethod
    def update(cls, old, data):
        raise NotImplementedError
