PROCEDURES = {
    "nvd": "CALL nvd_upsert(%(cve)s, %(created)s, %(updated)s, %(summary)s, %(cvss2)s, %(cvss3)s, %(vendors)s, %(cwes)s, %(source)s);",
    "advisory": "CALL advisory_upsert(%(created)s, %(updated)s, %(key)s, %(title)s, %(text)s, %(source)s, %(link)s, %(extras)s);",
    "events": "CALL change_events(%(cve)s, %(created)s, %(updated)s, %(commit)s, %(path)s, %(events)s)",
}
