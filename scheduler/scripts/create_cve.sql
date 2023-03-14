CREATE OR REPLACE PROCEDURE create_cve(
    name text, created timestamp, updated timestamp,  summary text, cvss2 dec, cvss3 dec, vendors jsonb, cwes jsonb, source jsonb
)
LANGUAGE plpgsql
AS $$
BEGIN

    -- add a new cve or update an existing one
    INSERT INTO opencve_cves (id, created_at, updated_at, cve_id, vendors, cwes, sources, summary, cvss2, cvss3)
    VALUES(uuid_generate_v4(), created, updated, name, vendors, cwes, source, summary, cvss2,cvss3)
    ON CONFLICT (cve_id) DO
    UPDATE SET updated_at = NOW(), summary = EXCLUDED.summary, cvss2 = EXCLUDED.cvss2, cvss3 = EXCLUDED.cvss3, vendors = EXCLUDED.vendors, cwes = EXCLUDED.cwes, sources = opencve_cves.sources || source;

    -- add the vendors


END;
$$;
