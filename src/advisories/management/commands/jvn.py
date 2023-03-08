"""from django.conf import settings

from core.management.commands import BaseCommand
from scheduler.sources.jvn import JvnFetcher


class Command(BaseCommand):
    def handle(self, *args, **options):
        self.info(self.style.MIGRATE_HEADING(f"Fetching JVN data..."))
        jvn = JvnFetcher({"jvn_path": settings.FETCHER_JVN_DATADIR})
        jvn.update()"""
