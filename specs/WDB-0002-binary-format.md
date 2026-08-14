# WDB-0002: Canonical binary format

Status: Normative Specification (v0.1 Frozen).

A record is a sequence of tagged fields ordered by strictly ascending unsigned field tag (`tag: u16be`). Duplicate field tags MUST be rejected. Each field uses the explicit grammar:
`tag: u16be | type: u8 | length: u32be | payload: length`

All multi-byte integers are big-endian. All fields, including fixed-width types, MUST specify their exact payload length in `length`.

## Envelope Header

The record envelope MUST begin with an 8-byte header:
- `magic[4]` = `0x57 0x44 0x42 0x01` (`WDB\x01`)
- `record_type: u8` (1=CHANGE, 2=VERSION, 3=CHECKPOINT, 4=ANCHOR, 5=INCIDENT, 6=RECOVERY)
- `flags: u16be` (reserved, MUST be `0x0000` in v0.1)
- `field_count: u16be` (number of tagged fields following header)

## Type Tags

- `00`: `NULL` (length 0)
- `01`: `BOOL` (length 1: `0x00` = false, `0x01` = true)
- `02`: `U64` (length 8, unsigned big-endian 64-bit integer)
- `03`: `I64` (length 8, signed big-endian two's-complement 64-bit integer)
- `04`: `UUID` (length 16, RFC 4122 network byte order)
- `05`: `UTF8` (valid UTF-8 string bytes, length = byte length)
- `06`: `BYTES` (raw byte array)
- `07`: `SHA256` (length 32, 32 raw binary hash bytes)
- `08`: `JSON-C14N` (Canonical JSON profile per RFC 8785: property keys sorted by UTF-16 code units, no unescaped whitespace, UTF-8 encoded)
- `09`: `DECIMAL` (ASCII UTF-8 string matching strict regex `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`. Exponents e.g. `1e5`, leading zeros e.g. `012`, and negative zeros `-0` / `-0.0` are FORBIDDEN)
- `10`: `TIMESTAMP_US` (length 8, signed I64 Unix microseconds UTC)

## CHANGE Record Required Fields (Ordered by Tag Ascending)

- **Tag 1**: `format_version` (Type `02 U64`, value `1`)
- **Tag 2**: `version_id` (Type `04 UUID`, 16 bytes)
- **Tag 3**: `transaction_id` (Type `05 UTF8`, transaction identifier string)
- **Tag 4**: `timestamp` (Type `10 TIMESTAMP_US`, 8 bytes I64)
- **Tag 5**: `table_id` (Type `05 UTF8`, canonical `"schema_name.table_name"`)
- **Tag 6**: `record_id` (Type `06 BYTES`, Canonical Primary Key Tuple binary encoding: `[col_count: u16be] + (col_name: UTF8 | type: u8 | val_len: u32be | val_bytes)...` sorted by column name ascending)
- **Tag 7**: `operation` (Type `02 U64`, 1=INSERT, 2=UPDATE, 3=DELETE)
- **Tag 8**: `field_set` (Type `08 JSON-C14N`, canonical JSON object `{"new":{...},"old":{...}}`)
- **Tag 9**: `provenance` (Type `08 JSON-C14N`, canonical JSON authorization provenance object)
- **Tag 10**: `previous_hash` (Type `07 SHA256`, 32 bytes)

Conformance requires bit-for-bit identical canonical binary output across all implementations and matching `specs/TEST-VECTORS.md`.
