# Handoff Report — Explorer 2: Adversarial Gateway & Threat Model Evaluation (R2)

## 1. Observation
- **Smart Contract Zero Verification**: In `blockchain/contracts/WolverineTrustRegistry.sol:81-154`, function `commitState` stores `customerSignature` and `agentSignature` as raw bytes in `StateCommitment` without calling `ecrecover`, RIP-7212, or any cryptographic signature verification routine. Furthermore, `commitmentDigest` is accepted as an arbitrary `bytes32` without validating that it equals the hash of the state parameters.
- **Submitter Shallow Check**: In `src/blockchain/besu/transaction_submitter.ts:11-23`, bBesuTransactionSubmitter` executes only string non-emptiness checks (`if (!input.customerSignatureHex || input.customerSignatureHex === '')h`) and performs zero signature validation.
- **Besu Integration Test Dummy Signatures**: In `tests/blockchain/besu_integration.test.ts:53-54`, test suites submit `crypto.randomBytes(64).toString('hex')` for both agent and customer signatures, and the test passes against the Besu client without error.
- **Gateway Daemon Architectural Disconnect**: In `src/daemons/wdb_gateway_daemon.ts:104-186`, `WdbGatewayDaemon.handleRequest()` collects attestations from validator endpoints and stores a `CanonicalQuorumCertificate` in memory, but **never calls BesuClient or BesuTransactionSubmitter**.
- **KMS Mock HMAC Forgery**: In `src/crypto/signing_provider.ts:110` and `:154` (`CloudKmsSigningProvider` and `HsmSigningProvider`), the classes silently fall back to `crypto.createHmac("sha512", this.config.keyArn).update(digest).digest()` when unconfigured, producing deterministic fake signatures from public key ARNs.
- **Missing Cloud SDK Dependencies**: In `package.json:70-74`, `@aws-sdk/client-kms` and `@google-cloud/kms` are absent from `dependencies`.
- **Preimage Incompatibilities**:
  1. `src/trust/commitment.ts:97-107`: Preimage is `WDB:CUST_AUTH:v1:` || `commitmentDigest` (32B) || `commitSeq` (8B uint64).
  2. `src/trust_network/commitment.ts:25-28`: Preimage is `WDB:TRUST:v1:` || canonical JSON, signed directly without auth prefix.
  3. `src/proof/universal_receipt_verifier.ts:91-96`: Preimage is `WDB:CUST_AUTH:v2:` || `checkpointDigest` (32B) || `commitSeq` (UTF-8 string), omitting `tenantId`, `databaseId`, `chainId`, and `contractAddress`.

## 2. Logic Chain
1. Under the Byzantine Gateway Operator model, the adversary controls the Gateway process, its TLS keys, and the Besu node operator Ethereum signing key.
2. Because `WolverineTrustRegistry.sol:commitState` is an unpermissioned `external` function without signature verification or `msg.sender` validation, the compromised Gateway can generate arbitrary state Merkle roots (R_fake) and dummy signature bytes.
3. When the compromised Gateway submits this transaction to Besu QBFT, the transaction succeeds, updates `latestSequence[tenantId][databaseId]`, and emits `CommitmentRecorded`.
4. While offline verifiers (`AirGappedProofVerifier`) will reject receipts signed with dummy keys, the on-chain canonical state is permanently locked at R_fake, preventing the genuine customer from committing legitimate state sequences due to `SequenceGapDetected` / `InvalidPreviousCommitment`.
5. Because preimages in `universal_receipt_verifier.ts` omit `tenantId` and `databaseId`, and all schemes omit `chainId` and `contractAddress`, valid signatures are vulnerable to cross-tenant and cross-environment replay attacks.
6. Because legacy `CloudKmsSigningProvider` creates HMAC signatures from public `keyArn` strings, fail-closed guarantees are violated.

3# 3. Caveats
- assumes that the underlying Besu QBFT validator set maintains an honest supermajority (>= 2f+1) and correctly enforces EVM consensus rules.
- Assumes the customer private key or Cloud KMS IAM permissions are not compromised outside of the Wolverine infrastructure.
- Assumes the customer executes `AirGappedProofVerifier` or `UniversalReceiptVerifier` on an isolated, uncompromised host with trusted public keys.

## 4. Conclusion
The claim that WolverineDB provides Byzantine Fault Tolerance against a compromised Gateway is **currently invalidated on the blockchain plane**. While off-chain TypeScript quorum checks exist in simulated clusters, the authoritative Besu smart contract layer possesses zero signature verification, allowing a Byzantine operator to poison or brick on-chain tenant state at will. Full remediation requires on-chain EIP-712 / Ed25519 signature checks, unified domain-separated preimages, removal of KMS HMAC simulation paths, and direct daemon-to-Besu transaction pipeline integration.

3# 5. Verification Method
- Inspect `blockchain/contracts/WolverineTrustRegistry.sol:81-154` to confirm lack of `ecrecover` or signature verification.
- Inspect `src/blockchain/besu/transaction_submitter.ts:11-23` and run `npx vitest run tests/blockchain/besu_integration.test.ts` to confirm acceptance of random bytes.
- Inspect `src/crypto/signing_provider.ts:110` to confirm presence of `createHmac("sha512", this.config.keyArn)`.
- Execute `npm test` across all 126 test suites (361 tests passing).
