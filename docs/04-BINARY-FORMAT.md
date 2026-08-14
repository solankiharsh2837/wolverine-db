# Binary format

WDB uses deterministic binary serialization prior to computing SHA-256 hashes. The envelope includes magic (`WDB\x01`), record type, flags, field count, format version, version ID, transaction ID, timestamp, table ID, primary key tuple (`record_id`), operation, field set, provenance envelope, and previous hash.

All multi-byte integers are big-endian. Strings are valid UTF-8; UUIDs are 16-byte RFC 4122 network order bytes; timestamps are signed 64-bit Unix microseconds UTC; `NULL` is type tag 0 with length 0.

## Value Encodings & Normalization Profiles (v0.1 Frozen)

- **JSON Canonicalization (`JSON-C14N`, Type 08)**: RFC 8785 canonical JSON profile. Object property keys are sorted by **UTF-16 code units**, without whitespace between elements, UTF-8 encoded.
- **Decimal Normalization (`DECIMAL`, Type 09)**: Normalized string matching `^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`. Scientific notation, leading zeros, and negative zero (`-0`) are forbidden.
- **Canonical Primary Key Tuple (`RECORD_ID`, Type 06)**: Serialized tuple `[col_count: u16be] + (col_name: UTF8 | type: u8 | val_len: u32be | val_bytes)...` sorted by column name ascending. Handles single, composite, and typed primary keys unambiguously.
- **Canonical Table Identifiers**: UTF-8 string `"schema_name.table_name"` (e.g. `"public.users"`).

Normative definitions and field tag orders are defined in [`specs/WDB-0002-binary-format.md`](file:///c:/Users/harsh/Documents/Codex/2026-08-13/referenced-chatgpt-conversation-this-is-an/wolverine-db/specs/WDB-0002-binary-format.md).
