import { TrustLedgerReplicaNode } from '../runtime/ledger_replica.js';
import { DirectMemoryNetworkTransport } from '../runtime/network_transport.js';

export interface StandaloneReplicaOptions {
  id: string;
  listenHost: string;
  listenPort: number;
  dataDir: string;
  role: 'PRIMARY' | 'BACKUP' | 'AUDIT';
}

export class StandaloneReplicaProcess {
  public readonly replica: TrustLedgerReplicaNode;

  constructor(options: StandaloneReplicaOptions, transport: DirectMemoryNetworkTransport) {
    this.replica = new TrustLedgerReplicaNode({
      replicaId: options.id,
      host: options.listenHost,
      port: options.listenPort,
      role: options.role,
    });
    this.replica.start(transport);
  }
}
