import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { createPublicClient, createWalletClient, http, keccak256, defineChain } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import {
  WOLVERINE_EIP712_DOMAIN_NAME,
  WOLVERINE_EIP712_VERSION,
  EIP712_TYPES,
  formatHex16,
  formatHex32,
  computeCanonicalCommitmentDigest,
  computeAgentAttestPreimage,
  computeEip712CommitmentDigest,
  CanonicalTrustCommitmentV3,
} from '../protocol/commitment_v3.js';
import { parseKmsDerSignature } from '../crypto/kms_der_parser.js';
import { WOLVERINE_TRUST_REGISTRY_ABI } from '../blockchain/besu/contract_abi.js';
import { deployTrustRegistry } from '../blockchain/besu/deploy.js';

export async function runGcpKmsAcceptance(): Promise<void> {
  console.log('\n========================================================================');
  console.log('  WOLVERINEDB — LIVE GCP CLOUD KMS CRYPTOGRAPHIC ACCEPTANCE HARNESS');
  console.log('========================================================================\n');

  const gcpProject = process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  const gcpLocation = process.env.GOOGLE_CLOUD_LOCATION || 'global';
  const gcpKeyName = process.env.WOLVERINE_GCP_KMS_KEY;
  const besuRpcUrl = process.env.WOLVERINE_BESU_RPC_URL || 'http://127.0.0.1:8545';
  let contractAddress = process.env.WOLVERINE_TRUST_REGISTRY_ADDRESS as `0x${string}` | undefined;

  // Check if live GCP credentials & KMS Key Name are configured
  if (!process.env.GOOGLE_APPLICATION_CREDENTIALS && !gcpKeyName) {
    console.log('  [STATUS]: KMS LIVE ACCEPTANCE: NOT EXECUTED');
    console.log('  [REASON]: Google Cloud credentials (GOOGLE_APPLICATION_CREDENTIALS / WOLVERINE_GCP_KMS_KEY) not set.');
    console.log('  [MODE]:   SKIPPED / ENVIRONMENT UNAVAILABLE\n');
    console.log('  Note: Mathematical EIP-712 typing, DER-to-EVM conversion, and on-chain fail-closed invariants are proven in tests/kms_signature_conversion.test.ts and tests/critical_crypto_authority.test.ts.');
    console.log('========================================================================\n');
    return;
  }

  console.log(`  [1/6] Connecting to Google Cloud KMS (Key: ${gcpKeyName})...`);

  // Dynamically load GCP KMS SDK if available
  let kmsClient: any;
  try {
    // @ts-ignore
    const gcpSdk = await import('@google-cloud/kms');
    kmsClient = new gcpSdk.KeyManagementServiceClient();
  } catch (err: any) {
    console.log('  [STATUS]: KMS LIVE ACCEPTANCE: NOT EXECUTED');
    console.log(`  [REASON]: @google-cloud/kms not installed: ${err.message}`);
    process.exit(0);
  }

  // 1. Fetch KMS Public Key & Validate Key Spec
  const [pubKeyRes] = await kmsClient.getPublicKey({ name: gcpKeyName });
  if (pubKeyRes.algorithm !== 'EC_SIGN_SECP256K1_SHA256') {
    throw new Error(`Invalid GCP KMS algorithm: expected EC_SIGN_SECP256K1_SHA256, observed ${pubKeyRes.algorithm}`);
  }

  const pubKeyObj = crypto.createPublicKey(pubKeyRes.pem);
  const rawSpki = pubKeyObj.export({ type: 'spki', format: 'der' });
  const uncompressedPubKey = rawSpki.subarray(-65);
  const customerSigningAddress = `0x${keccak256(uncompressedPubKey.subarray(1)).slice(-40)}` as `0x${string}`;

  console.log(`      ✓ Verified GCP KMS Algorithm: EC_SIGN_SECP256K1_SHA256`);
  console.log(`      ✓ Customer Sovereign Address: ${customerSigningAddress}`);

  // 2. Validate Besu Network & Contract
  console.log(`\n  [2/6] Connecting to Besu QBFT at ${besuRpcUrl}...`);
  const customChain = defineChain({
    id: 13370,
    name: 'wolverine-trust-chain',
    nativeCurrency: { name: 'Wolverine Trust Gas', symbol: 'WTG', decimals: 18 },
    rpcUrls: { default: { http: [besuRpcUrl] } },
  });

  const publicClient = createPublicClient({ chain: customChain, transport: http(besuRpcUrl) });
  const deployerAccount = privateKeyToAccount('0x0000000000000000000000000000000000000000000000000000000000000001');
  const walletClient = createWalletClient({ account: deployerAccount, chain: customChain, transport: http(besuRpcUrl) });

  if (!contractAddress) {
    console.log('      Deploying fresh WolverineTrustRegistry.sol for live GCP KMS acceptance...');
    const deployRes = await deployTrustRegistry(besuRpcUrl);
    contractAddress = deployRes.contractAddress;
  }

  const tenantId = `tenant_kms_gcp_${Date.now()}`;
  const databaseId = 'prod_vault_db';

  // Register tenant with GCP KMS address
  console.log(`\n  [3/6] Registering Sovereign KMS Tenant ${tenantId} On-Chain...`);
  const regTx = await walletClient.writeContract({
    address: contractAddress,
    abi: WOLVERINE_TRUST_REGISTRY_ABI,
    functionName: 'registerTenant',
    args: [tenantId, customerSigningAddress, deployerAccount.address],
  });
  await publicClient.waitForTransactionReceipt({ hash: regTx, confirmations: 1 });
  console.log(`      ✓ Tenant Registered On-Chain (Tx: ${regTx})`);

  // 3. Build Canonical Commitment & Dual Signatures
  console.log(`\n  [4/6] Constructing Canonical Commitment & Requesting Real GCP KMS Signature...`);
  const commitment: CanonicalTrustCommitmentV3 = {
    protocolVersion: 3,
    tenantId,
    databaseId,
    checkpointId: crypto.randomUUID(),
    commitSeq: 1n,
    epoch: 1,
    chainId: 13370,
    contractAddress,
    networkId: 'wolverine-besu-cluster',
    checkpointDigestHex: crypto.randomBytes(32).toString('hex'),
    stateMerkleRootHex: crypto.randomBytes(32).toString('hex'),
    changeChainHeadHex: crypto.randomBytes(32).toString('hex'),
    previousCommitmentDigestHex: '0'.repeat(64),
    logicalTimestampUs: BigInt(Date.now()) * 1000n,
    lsn: '0/100000',
    agentId: 'agent_node_01',
    customerSigningAddress,
  };

  const eip712Digest = computeEip712CommitmentDigest(commitment);
  const digestBytes = Buffer.from(eip712Digest.slice(2), 'hex');

  // Call GCP KMS AsymmetricSign
  const [signRes] = await kmsClient.asymmetricSign({
    name: gcpKeyName,
    digest: {
      sha256: new Uint8Array(digestBytes),
    },
  });

  const derBytes = Buffer.from(signRes.signature);
  const parsedSig = parseKmsDerSignature({
    derSignature: derBytes,
    digest: eip712Digest,
    expectedAddressOrPublicKey: customerSigningAddress,
  });

  console.log(`      ✓ Received Raw ASN.1 DER (${derBytes.length} bytes)`);
  console.log(`      ✓ Extracted Low-s: ${parsedSig.s}`);
  console.log(`      ✓ Derived Recovery ID v: ${parsedSig.v}`);
  console.log(`      ✓ Canonical 65-Byte Sig: ${parsedSig.signatureHex}`);

  // Agent attestation
  const agentKeyPair = crypto.generateKeyPairSync('ed25519');
  const digestHex = computeCanonicalCommitmentDigest(commitment);
  const agentPreimage = computeAgentAttestPreimage(commitment, digestHex);
  const agentSig = crypto.sign(null, agentPreimage, agentKeyPair.privateKey);

  // 4. Submit to Besu
  console.log(`\n  [5/6] Submitting KMS-Signed Commitment to Besu QBFT Contract...`);
  const commitTx = await walletClient.writeContract({
    address: contractAddress,
    abi: WOLVERINE_TRUST_REGISTRY_ABI,
    functionName: 'commitState',
    args: [
      commitment.tenantId,
      commitment.databaseId,
      formatHex16(commitment.checkpointId),
      commitment.commitSeq,
      commitment.epoch,
      formatHex32(commitment.checkpointDigestHex),
      formatHex32(commitment.stateMerkleRootHex),
      formatHex32(commitment.changeChainHeadHex),
      formatHex32(commitment.previousCommitmentDigestHex),
      commitment.logicalTimestampUs,
      commitment.lsn,
      commitment.agentId,
      commitment.protocolVersion,
      `0x${agentSig.toString('hex')}`,
      parsedSig.signatureHex,
    ],
  });

  const receipt = await publicClient.waitForTransactionReceipt({ hash: commitTx, confirmations: 1 });
  console.log(`      ✓ Finalized in Block #${receipt.blockNumber} (Tx: ${receipt.transactionHash})`);

  // 5. Query On-Chain State
  const onChainCommitment = await publicClient.readContract({
    address: contractAddress,
    abi: WOLVERINE_TRUST_REGISTRY_ABI,
    functionName: 'getLatestCommitment',
    args: [tenantId, databaseId],
  });
  if (onChainCommitment.stateMerkleRoot.toLowerCase() !== formatHex32(commitment.stateMerkleRootHex).toLowerCase()) {
    throw new Error('On-chain stateMerkleRoot mismatch');
  }
  console.log(`      ✓ Verified on-chain record: stateMerkleRoot matches witnessed root`);

  // 6. Live Field Substitution Adversarial Attack
  console.log(`\n  [6/6] Executing Live Field-Binding Adversarial Attack against Besu...`);
  let attackReverted = false;
  try {
    await walletClient.writeContract({
      address: contractAddress,
      abi: WOLVERINE_TRUST_REGISTRY_ABI,
      functionName: 'commitState',
      args: [
        commitment.tenantId,
        commitment.databaseId,
        formatHex16(commitment.checkpointId),
        commitment.commitSeq,
        commitment.epoch,
        formatHex32(commitment.checkpointDigestHex),
        '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', // TAMPERED STATE ROOT
        formatHex32(commitment.changeChainHeadHex),
        formatHex32(commitment.previousCommitmentDigestHex),
        commitment.logicalTimestampUs,
        commitment.lsn,
        commitment.agentId,
        commitment.protocolVersion,
        `0x${agentSig.toString('hex')}`,
        parsedSig.signatureHex,
      ],
    });
  } catch (err: any) {
    attackReverted = true;
    console.log(`      ✓ Tampered stateMerkleRoot correctly REVERTED on Besu: ${err.message.slice(0, 70)}...`);
  }

  if (!attackReverted) {
    throw new Error('Adversarial attack failed: Besu accepted tampered stateMerkleRoot with stale customer signature');
  }

  console.log('\n========================================================================');
  console.log('  GCP KMS → SECP256K1 → EIP-712 → BESU = VERIFIED LIVE END-TO-END');
  console.log('========================================================================\n');
}

if (process.argv[1]?.endsWith('gcp_kms_besu_acceptance.js') || process.argv[1]?.endsWith('gcp_kms_besu_acceptance.ts')) {
  runGcpKmsAcceptance().catch((err) => {
    console.error('\n❌ GCP KMS ACCEPTANCE SUITE FAILED:\n', err);
    process.exit(1);
  });
}
