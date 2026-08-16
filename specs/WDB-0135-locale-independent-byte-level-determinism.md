# WDB-0135: Locale-Independent Byte-Level Determinism

**Status**: Normative (Frozen)  
**Version**: 1.3.0  
**Domain**: Binary Normalization & State Determinism

---

## 1. Abstract

This specification mandates deterministic UTF-8 byte-level ordering across all primary keys, record fields, JSON object keys, and Merkle leaf sorting operations, eliminating system-locale and runtime collation dependencies.

---

## 2. Invariants

1. **Byte-Level Collation**: For any two strings $S_1, S_2$, their canonical relative order is defined by lexicographical comparison of their raw UTF-8 byte sequences:
   $$\text{CompareCanonicalStrings}(S_1, S_2) = \text{Buffer.compare}(\text{UTF8}(S_1), \text{UTF8}(S_2))$$
2. **Prohibition of `localeCompare`**: JavaScript `String.prototype.localeCompare()` is strictly prohibited in all cryptographic and state serialization paths.
3. **Cross-Platform Equality**: The identical logical state evaluated on Linux, macOS, or Windows across any system locale MUST yield bitwise-identical Merkle checkpoint roots.
