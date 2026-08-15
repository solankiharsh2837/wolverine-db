import { describe, it, expect } from 'vitest';

describe('External Checkpoint Store (WDB-0011 Scaffolding)', () => {
  it('enforces immutable retention contract', async () => {
    // In-memory mock implementing WDB-0011 CheckpointStore semantics
    const store = new Map<string, { id: string; digest: string }>();

    const putCheckpoint = async (id: string, digest: string) => {
      if (store.has(id)) {
        const existing = store.get(id)!;
        if (existing.digest !== digest) {
          throw new Error('CheckpointConflictError: Immutability violation');
        }
        return; // Idempotent
      }
      store.set(id, { id, digest });
    };

    await putCheckpoint('chk-1', 'digest-1');
    expect(store.has('chk-1')).toBe(true);

    // Attempting to overwrite with differing payload throws conflict
    await expect(putCheckpoint('chk-1', 'digest-tampered')).rejects.toThrow(
      'CheckpointConflictError'
    );
  });
});
