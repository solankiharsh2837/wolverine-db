# Trust Receipt Chains & Standalone Verification

Trust Receipts form a cryptographic hash-linked chain across time:

```text
Receipt #5000 ──(previousReceiptDigest)──> Receipt #5001 ──> Receipt #5002
```

## Chain Verification
- Detects Gaps ($S_i \ne S_{i-1} + 1$).
- Detects Forks (competing digests for same sequence).
- Detects Replays and Rollbacks.
- 100% Offline Verifiable without Wolverine cloud access.
