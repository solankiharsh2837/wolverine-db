import crypto from 'node:crypto';
import { ActorBaselineProfile } from './types.js';
import { canonicalizeJson } from '../binary/c14n.js';
import { timingSafeEqualHashes } from '../crypto/hash.js';

export function computeBaselineHash(profile: Omit<ActorBaselineProfile, 'baselineHash'>): Buffer {
  const domain = Buffer.from('WDB:BASELINE:v1:', 'utf8');
  const actorBuf = Buffer.from(profile.actorId, 'utf8');
  const actorLenBuf = Buffer.alloc(2);
  actorLenBuf.writeUInt16BE(actorBuf.length, 0);

  const canonicalJsonStr = canonicalizeJson({
    allowedScopes: profile.allowedScopes,
    typicalOperations: profile.typicalOperations,
    maintenanceWindows: profile.maintenanceWindows,
    maxMutationsPerMinute: profile.maxMutationsPerMinute,
    averageBatchSize: profile.averageBatchSize,
    requiresTicketProvenance: profile.requiresTicketProvenance,
  });
  const jsonBuf = Buffer.from(canonicalJsonStr, 'utf8');

  const preimage = Buffer.concat([domain, actorLenBuf, actorBuf, jsonBuf]);
  return crypto.createHash('sha256').update(preimage).digest();
}

export class BaselineTracker {
  private profiles = new Map<string, ActorBaselineProfile>();

  public registerBaseline(profileData: Omit<ActorBaselineProfile, 'baselineHash'>): ActorBaselineProfile {
    const baselineHash = computeBaselineHash(profileData);
    const profile: ActorBaselineProfile = {
      ...profileData,
      baselineHash,
    };
    this.profiles.set(profile.actorId, profile);
    return profile;
  }

  public getBaseline(actorId: string): ActorBaselineProfile | null {
    const profile = this.profiles.get(actorId);
    if (!profile) return null;

    // Verify baseline integrity
    const computed = computeBaselineHash(profile);
    if (!timingSafeEqualHashes(computed, profile.baselineHash)) {
      return null; // Tampered
    }
    return profile;
  }

  public verifyBaselineIntegrity(actorId: string): boolean {
    const profile = this.profiles.get(actorId);
    if (!profile) return false;
    const computed = computeBaselineHash(profile);
    return timingSafeEqualHashes(computed, profile.baselineHash);
  }
}
