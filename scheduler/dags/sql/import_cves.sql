COPY opencve_cves_bis(id, created_at, updated_at, cve_id, vendors, cwes, summary, cvss2, cvss3)
FROM '/tmp/cve.csv'
DELIMITER ','
CSV HEADER;