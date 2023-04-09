CREATE OR REPLACE PROCEDURE advisory_upsert(created timestamp, updated timestamp, key text, title text, text text, source text, link text, extras jsonb)
LANGUAGE SQL
AS $$
    -- add a new cve or update an existing one
    INSERT INTO opencve_advisories (id, created_at, updated_at, key, title, text, source, link, extras)
    VALUES(uuid_generate_v4(), created, updated, key, title, text, source, link, extras)
    ON CONFLICT (key) DO NOTHING;

    -- todo: create the CVE
$$;