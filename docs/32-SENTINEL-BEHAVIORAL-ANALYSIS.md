# Sentinel Behavioral Anomaly Detection

Sentinel monitors transactional change feeds to identify subtle, unauthorized, or compromised administrative mutations that bypass application-level ACLs.

## Detection Dimensions

1. **Maintenance Window Deviations**: DBA or service accounts executing bulk updates outside registered maintenance hours.
2. **Unauthorized Scope Traversal**: Service accounts mutating tables outside their registered baseline permissions.
3. **High-Frequency Velocity Spikes**: Rapid modifications exceeding 3x the standard mutation velocity baseline.
4. **Missing Ticket Provenance**: Critical mutations executed without binding change management ticket IDs.

## Baseline Integrity

To prevent malicious administrators from poisoning behavioral baselines to disguise ongoing attacks, all baseline profiles are cryptographically hashed (`WDB:BASELINE:v1:`) and committed to `wolverine_sys.baselines`. Any unauthorized modification of the baseline tables triggers immediate incident escalation.
