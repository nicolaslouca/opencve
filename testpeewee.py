#!/usr/bin/python

import peewee
from peewee import *

import datetime

#db = peewee.SqliteDatabase('test.db')
psql_db = PostgresqlDatabase('opencve')

class Cve(peewee.Model):

    cve_id = peewee.CharField()
    created_at = peewee.DateField(default=datetime.date.today)
    payload = peewee.CharField()

    class Meta:
        database = psql_db
        db_table = 'opencve_cves'

query = Cve.select().where(Cve.id == True)
query = Cve.insert(cve_id="CVE-2023-1234").on_conflict(conflict_target=(Cve.cve_id,), update={Cve.payload: 'foobar'})
print(query)
