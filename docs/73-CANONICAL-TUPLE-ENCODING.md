# WolverineDB Canonical Protocol Tuple Encoding Architecture

---

## 1. Ambiguity Problem in Cryptographic Signatures

Raw byte concatenation without length prefixing is vulnerable to boundary shifting:

$$\text{Concat}(\text{"AB"}, \text{"C"}) == \text{Concat}(\text{"A"}, \text{"BC"}) == \text{"ABC"}$$

If a cryptographic signature signs $\text{"ABC"}$, it cannot distinguish whether the first field was $\text{"AB"}$ or $\text{"A"}$.

---

## 2. The Canonical Tuple Wire Standard

`encodeProtocolTuple(domain, fields)` prepends a domain string followed by length-prefixed, type-tagged field blocks:

```text
[Domain: UTF8]
  ├── [Type: 0x01 STRING]  [Len: 4 bytes u32be] [UTF8 Bytes]
  ├── [Type: 0x02 BUFFER]  [Len: 4 bytes u32be] [Raw Bytes]
  ├── [Type: 0x03 INT32]   [Value: 4 bytes i32be]
  └── [Type: 0x04 INT64]   [Value: 8 bytes i64be]
```

### Deterministic Benefits
1. **Second-Preimage Resistance**: No combination of field values can yield the same binary serialization as another distinct combination.
2. **Domain Separation**: Incompatible message types cannot collide across protocol layers.
3. **Locale-Independence**: Combined with `compareCanonicalStrings()`, UTF-8 byte ordering ensures identical cryptographic digests across any machine or operating system.
