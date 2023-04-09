CREATE OR REPLACE PROCEDURE change_events(
    cve_name text,
    created timestamp,
    updated timestamp,
    commit text,
    path text,
    events jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _change_id uuid;
   _cve_id    uuid;
   _event     json;
BEGIN
    -- retrieve the cve ID
    SELECT id INTO _cve_id FROM opencve_cves WHERE cve_id = cve_name;

    -- create a new change
    _change_id := uuid_generate_v4();
    INSERT INTO opencve_changes (id, created_at, updated_at, cve_id, commit, path)
    VALUES(_change_id, created, updated, _cve_id, commit, path);

    -- add the events in it
    FOR _event IN SELECT * FROM json_array_elements(events::json)
    LOOP
        INSERT INTO opencve_events (id, created_at, updated_at, change_id, cve_id, type, details)
        VALUES(uuid_generate_v4(), created, updated, _change_id, _cve_id, trim('"' FROM (_event -> 'type')::text), _event -> 'details');
    END LOOP;

END;
$$;

-- CALL change_events('CVE-2023-1234', '2023-03-15T00:00:00.000000+00:00','2023-03-15T00:00:00.000000+00:00', 'e55795856f710d593b8b7392422f27d758b77f19', 'nvd/2023/CVE-2023-1234', '[]');