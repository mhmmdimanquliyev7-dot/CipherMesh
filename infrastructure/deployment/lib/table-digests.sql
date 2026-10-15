-- Row count and SHA-256 digest of every application table (backup manifest and restore drill,
-- ADR-014). The digest covers the full text form of every row in a deterministic order, so two
-- databases with equal digests hold identical rows: ciphertext, wrapped keys, envelopes, metadata.
-- Output: one "table|rows|sha256-hex" line per table. Contains no row content.
-- Session settings fix the text form of timestamps, numbers and bytes on both databases.
SET TimeZone = 'UTC';
SET DateStyle = 'ISO, MDY';
SET IntervalStyle = 'postgres';
SET extra_float_digits = 1;
SET bytea_output = 'hex';
SELECT format('%s|%s|%s', t.table_name, d.row_count, d.digest)
FROM information_schema.tables AS t
CROSS JOIN LATERAL (
  SELECT
    (xpath('/row/n/text()', x))[1]::text AS row_count,
    coalesce((xpath('/row/h/text()', x))[1]::text, 'empty') AS digest
  FROM query_to_xml(
    format(
      'SELECT count(*) AS n, encode(sha256(convert_to(string_agg(r::text, E''\n'' ORDER BY r::text), ''UTF8'')), ''hex'') AS h FROM %I.%I AS r',
      t.table_schema,
      t.table_name
    ),
    false, true, ''
  ) AS x
) AS d
WHERE t.table_schema = 'public' AND t.table_type = 'BASE TABLE'
ORDER BY t.table_name;
