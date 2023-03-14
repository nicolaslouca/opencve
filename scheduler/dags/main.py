import json
import logging
import pathlib

import git
import pendulum
from airflow import AirflowException
from airflow.configuration import conf
from airflow.decorators import dag, task
from airflow.models import Variable
from airflow.utils.task_group import TaskGroup

from changes import Handlers
from sources import BaseSource
from utils import import_submodules

# Automatically import sources
import_submodules("sources")

DEFAULT_REMOTE_REPO = "https://github.com/opencve/opencve-kb.git"
REMOTE_REPO = conf.get("opencve", "remote_repo_url", fallback=DEFAULT_REMOTE_REPO)
LOCAL_REPO = pathlib.Path(conf.get("opencve", "local_repo_path"))

logger = logging.getLogger(__name__)


@dag(
    schedule="0 * * * *",
    start_date=pendulum.datetime(2023, 1, 1, tz="UTC"),
    catchup=False,
    max_active_runs=1,
)
def sources():
    @task()
    def git_pull():
        LOCAL_REPO.mkdir(parents=True, exist_ok=True)

        # First time the scheduler is launched, we clone the repo
        if not pathlib.Path.exists(LOCAL_REPO / ".git"):
            logger.info(f"Cloning {REMOTE_REPO} into {LOCAL_REPO}...")
            repo = git.Repo.clone_from(REMOTE_REPO, LOCAL_REPO)
            logger.info(f"Repo {LOCAL_REPO} is now cloned (HEAD: {repo.head.commit})")
            return

        # Check if remotes well configured
        repo = git.Repo(LOCAL_REPO)
        remotes = repo.remotes

        if not remotes:
            raise AirflowException(f"Repo {LOCAL_REPO} has no remote.")

        # Pull the last changes
        last_commit = repo.head.commit
        logger.info(f"Local HEAD is {last_commit}")
        logger.info(f"Pulling last changes from {REMOTE_REPO}...")
        repo.remotes.origin.pull("main")

        if last_commit == repo.head.commit:
            logger.info(f"No change detected")
            return

        logger.info(f"New HEAD is {repo.head.commit})")

    @task()
    def git_push(**context):
        logger.info(f"Local repository: {LOCAL_REPO}")
        repo = git.Repo(LOCAL_REPO)

        if not repo.is_dirty(untracked_files=True):
            logger.info(f"No change detected")
            return

        # Add all modified files
        logger.info(f"Adding changes")
        repo.git.add(all=True)

        # Create the new commit and push changes
        logger.info("Commiting changes")
        execution_date = context.get("execution_date").strftime("%Y-%m-%d, %H:%M:%S %Z")
        author = git.Actor("OpenCVE", "git@opencve.io")
        repo.index.commit(f"Revision {execution_date}", author=author)

        logger.info("Pushing changes")
        repo.remotes.origin.push("main")
        logger.info(f"Remote {REMOTE_REPO} updated")

    @task
    def update_source(source_cls):
        instance = source_cls(path=LOCAL_REPO / source_cls.name)
        instance.run()

    @task
    def analyse_changes():
        repo = git.Repo(LOCAL_REPO)

        # First execution, save the commit hash but skip the changes analysis
        last_commit_hash = Variable.get("last_commit_hash", default_var=None)
        if not last_commit_hash:
            Variable.set("last_commit_hash", repo.head.commit.hexsha)
            logger.info("First execution, skip the changes analysis")
            return

        # List of commits since the last analysis
        commits = [c for c in repo.iter_commits(rev=f"{last_commit_hash}..HEAD")]
        if not commits:
            logger.info(f"No diff to parse")
            return

        logger.info(
            f"Analysing {len(commits)} commit(s) ({last_commit_hash}:{repo.head.commit.hexsha})"
        )

        # List the diffs between last analysed commit and current one
        diffs = repo.commit(last_commit_hash).diff(repo.head.commit)

        # Parse the diffs and execute their handler
        logger.info(f"Parsing {len(diffs)} diffs")
        for diff in diffs:
            handler = Handlers(diff)
            handler.execute()

        # Save the last know commit
        Variable.set("last_commit_hash", repo.head.commit)

    # Option 1 - Use the official OpenCVE KB
    if conf.getboolean("opencve", "use_official_kb"):
        git_pull() >> analyse_changes()

    # Option 2 - Maintain a KB
    else:

        # Group all the sources task in a single TaskGroup
        with TaskGroup(group_id="sources") as sources_gt:
            sources_cls = [s for s in BaseSource.__subclasses__()]
            sources_tasks = []
            for source_cls in sources_cls:
                foo = update_source.override(task_id=source_cls.name)(source_cls)
                sources_tasks.append(foo)

        (git_pull() >> sources_gt >> git_push() >> analyse_changes())


sources()
