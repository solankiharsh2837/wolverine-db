# Test vectors

Status: Normative Specifications (v0.1 Frozen).

All implementations MUST pass these exact cross-language test vectors unchanged.

---

## 1. Domain-Separated Constants & Empty Merkle Root

- **Domain Tag (`EMPTY_ROOT`)**: `"WDB:EMPTY_ROOT:v1"`
- **Empty Merkle Root Hash**: `8e4f2728690f5b33a7e61d15881334c705770f18450ecdc1c3b77f02f3df6024`
- **Genesis Predecessor Hash**: `0000000000000000000000000000000000000000000000000000000000000000` (32 zero bytes)

---

## 2. Merkle Leaf & Node Hash Formulas

### Leaf Hash Test Vector
- **Domain Tag**: `"WDB:LEAF:v1"`
- **Input Payload**: ASCII `"test_leaf_payload"` (17 bytes: `746573745f6c6561665f7061796c6f6164`)
- **Length Prefix (`u32be`)**: `00000011`
- **Computed Leaf Hash**: `1e6ebc3db5f2c97294b84401ed2722cc84ddd3ae5b946ede528edda2ffc9674b`

### Internal Node Hash Test Vector
- **Domain Tag**: `"WDB:NODE:v1"`
- **Left Hash**: 32 bytes of `0x01` (`010101...01`)
- **Right Hash**: 32 bytes of `0x02` (`020202...02`)
- **Computed Node Hash**: `bca27582de55580e19701dd8a76955d3162a7f4c8f927a7f0d4910d02d8660bc`

---

## 3. RFC 8785 Canonical JSON (`JSON-C14N`)

- **Input Object**: `{ "b": 1, "a": 2, "10": 3 }`
- **UTF-16 Code Unit Property Key Order**: `"10"` (0x31 0x30), `"a"` (0x61), `"b"` (0x62)
- **Canonical UTF-8 String Output**: `{"10":3,"a":2,"b":1}`
- **Canonical Hex Bytes**: `7b223130223a332c2261223a322c2262223a317d`

---

## 4. Canonical Primary Key Tuple (`RECORD_ID`)

- **Input Primary Key**: Column `"id"` = `42` (`U64`, big-endian unsigned 64-bit integer)
- **Column Count (`u16be`)**: `0001`
- **Column Name (`u16be len + UTF8`)**: `0002` + `"id"` (`6964`)
- **Type (`u8`)**: `02` (U64)
- **Value Length (`u32be`)**: `00000008`
- **Value Payload (8 bytes BE)**: `000000000000002a`
- **Canonical Tuple Hex**: `0001000269640200000008000000000000002a`

---

## 5. Canonical `CHANGE` Record Binary Envelope & Hash

- **Record Type**: `1` (`CHANGE`)
- **Format Version**: `1` (Tag 1, `U64`)
- **Version ID**: Nil UUID `00000000-0000-0000-0000-000000000000` (Tag 2, `UUID`)
- **Transaction ID**: `"tx:1001"` (Tag 3, `UTF8`)
- **Timestamp**: `0` microseconds (Tag 4, `TIMESTAMP_US`)
- **Table ID**: `"public.users"` (Tag 5, `UTF8`)
- **Record ID**: Primary key tuple `"id"` = `42` (Tag 6, `BYTES` hex `0001000269640200000008000000000000002a`)
- **Operation**: `1` (`INSERT`, Tag 7, `U64`)
- **Field Set**: `{"new":{"name":"Alice"},"old":null}` (Tag 8, `JSON-C14N`)
- **Provenance**: `{"actor":"user1"}` (Tag 9, `JSON-C14N`)
- **Previous Hash**: 32 zero bytes (Tag 10, `SHA256`)
- **Total Envelope Byte Length**: 241 bytes
- **Canonical Envelope Hex**:
  `57444201010000000a00010200000008000000000000000100020400000010000000000000000000000000000000000003050000000774783a3130303100040a0000000800000000000000000005050000000c7075626c69632e7573657273000606000000130001000269640200000008000000000000002a000702000000080000000000000001000808000000237b226e6577223a7b226e616d65223a22416c696365227d2c226f6c64223a6e756c6c7d000908000000117b226163746f72223a227573657231227d000a07000000200000000000000000000000000000000000000000000000000000000000000000`
- **Expected Change Hash (`SHA256`)**: `71ae3610dd6022516bae0156f220baa1a0e5408b76aba8f98ffe44a89fa6e9f3`

---

## 6. Ed25519 Policy Approval Envelope Signature

- **Incident ID**: `01010101-0101-0101-0101-010101010101`
- **Scope**: `"public.users"`
- **Target Version ID**: `02020202-0202-0202-0202-020202020202`
- **Proposed Changes Hash**: 32 bytes of `0x03` (`030303...03`)
- **Requester ID**: `"admin@example.com"`
- **Approver Ed25519 Public Key (Hex)**: `c225c99bf94417cc2f4b50d5e7f1b0e4f7ad1e185316244fd6ca0ae13aa65db7`
- **Nonce**: `04040404-0404-0404-0404-040404040404`
- **Expires At**: `1800000000000000` microseconds (`0006651728988000` hex I64)
- **Canonical Payload Hex**: `010101010101010101010101010101017075626c69632e757365727302020202020202020202020202020202030303030303030303030303030303030303030303030303030303030303030361646d696e406578616d706c652e636f6dc225c99bf94417cc2f4b50d5e7f1b0e4f7ad1e185316244fd6ca0ae13aa65db7040404040404040404040404040404040006651728988000`
- **Ed25519 Signature Hex**: `57631171f877c0a6e8e7ce298ec10ade8ebc16139606e658196a67aedf55a8926b671447a3cccf407dd3d53ff811e38f2c6a248fc535ba91bcaaab5c01a2f902`

---

## 7. Negative Test Cases

Implementations MUST reject the following malformed data:
1. **Invalid Magic Header**: Headers starting with bytes other than `0x57 0x44 0x42 0x01` (`WDB1xx` error).
2. **Unsorted Field Tags**: Fields where tag $n+1 \le$ tag $n$ (`WDB1xx` error).
3. **Duplicate Field Tags**: Multiple fields with identical tags (`WDB1xx` error).
4. **Invalid Decimal String**: Decimals containing exponents (e.g. `"1e5"`), leading zeros (e.g. `"012"`), or negative zero (`"-0"`, `"-0.0"`) (`WDB1xx` error).
5. **Requester = Approver**: Approval envelope where `approver_pubkey` matches `requester_id` (`WDB6xx` error).
6. **Expired Approval Signature**: Envelope timestamp `expires_at` less than execution timestamp (`WDB6xx` error).
7. **Tampered Change Record**: Modifying any field payload causes `change_hash` mismatch (`WDB3xx` error).
8. **Altered Sibling Proof**: Merkle proof sibling hash mutation causes root mismatch (`WDB3xx` error).
