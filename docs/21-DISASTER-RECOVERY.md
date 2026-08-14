# Disaster recovery

Plan for PostgreSQL loss, history-store loss, object-store outage, anchor outage, missing checkpoint, partial corruption, and complete database corruption. Restore uses ordinary database backups first, then verifies the restored state against retained WDB history and independent checkpoints.

Reconstruction solely from immutable history is an eventual capability, not a v0.1 promise. Retention, backup media, restore runbooks, recovery-point objectives, and recovery-time objectives are deployment-specific and **UNRESOLVED**.
