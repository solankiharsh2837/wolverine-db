# Integrity verification

Verification checks canonical decoding, per-stream predecessor links, version-parent links, state leaves, Merkle roots, checkpoint records, and optional external anchors. It reports the smallest verified scope and the first unverified boundary rather than claiming global trust after a partial check.

Outcomes include valid, mismatch, missing history, malformed record, unavailable dependency, and indeterminate. A Merkle mismatch triggers localization; history mutation or deletion triggers a chain/checkpoint failure; an unavailable anchor is an availability condition, not proof of tampering.
