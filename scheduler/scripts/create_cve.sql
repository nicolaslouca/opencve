CREATE OR REPLACE PROCEDURE create_cve(
    cve_name text,
    created timestamp,
    updated timestamp,
    summary text,
    cvss2 dec,
    cvss3 dec,
    vendors jsonb,
    cwes jsonb,
    source jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _cwe       text;
   _vendors   text;
   _vendor    text;
   _vendor_id text;
   _product   text;
BEGIN
    -- add a new CVE or update an existing one
    INSERT INTO opencve_cves (id, created_at, updated_at, cve_id, vendors, cwes, sources, summary, cvss2, cvss3)
    VALUES(uuid_generate_v4(), created, updated, cve_name, vendors, cwes, source, summary, cvss2,cvss3)
    ON CONFLICT (cve_id) DO
    UPDATE SET
      updated_at = NOW(),
      summary = EXCLUDED.summary,
      cvss2 = EXCLUDED.cvss2,
      cvss3 = EXCLUDED.cvss3,
      vendors = EXCLUDED.vendors,
      cwes = EXCLUDED.cwes,
      sources = opencve_cves.sources || source;

    -- add the new CWEs
    FOR _cwe IN SELECT * FROM json_array_elements_text(cwes::json)
    LOOP
      INSERT INTO opencve_cwes (id, created_at, updated_at, cwe_id)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _cwe)
      ON CONFLICT (cwe_id) DO NOTHING;
    END LOOP;

    -- add the new Vendors & Products
    FOR _vendors IN SELECT * FROM json_array_elements_text(vendors::json)
    LOOP
      _vendor := split_part(_vendors, '$PRODUCT$', 1);
      _product := split_part(_vendors, '$PRODUCT$', 2);

      -- insert the vendor
      INSERT INTO opencve_vendors (id, created_at, updated_at, name)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _vendor)
      ON CONFLICT (name) DO NOTHING;

      -- retrieve its ID
      SELECT id INTO _vendor_id FROM opencve_vendors WHERE name = _vendor;

      -- insert the product
      INSERT INTO opencve_products (id, created_at, updated_at, vendor_id, name)
      VALUES(uuid_generate_v4(), NOW(), NOW(), _vendor_id::uuid, _product)
      ON CONFLICT (name, vendor_id) DO NOTHING;
    END LOOP;
END;
$$;

-- Create a CVE
CALL create_cve('CVE-2022-40000', '2023-03-15T00:00:00.000000+00:00','2023-03-15T00:00:00.000000+00:00', 'CVE-2023-1234', 10, 10, '["foo$PRODUCT$bar", "foo$PRODUCT$baz"]', '["foo", "bar"]', '{"nvd": "nvd/2023/CVE-2023-1234.json"}');

-- Display created rows
SELECT id, cve_id, vendors, cwes, sources FROM opencve_cves ORDER BY updated_at DESC LIMIT 1;
SELECT id, cwe_id FROM opencve_cwes ORDER BY updated_at DESC  LIMIT 2;
SELECT id, name FROM opencve_vendors ORDER BY updated_at DESC  LIMIT 1;
SELECT id, vendor_id, name FROM opencve_products ORDER BY updated_at DESC  LIMIT 2;
