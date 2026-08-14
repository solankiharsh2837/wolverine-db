# Coding standards

Use strict TypeScript types for public code, explicit error codes, deterministic serialization, and small modules with clear ownership. Validate all external input at boundaries and avoid implicit coercion, locale-dependent formatting, wall-clock ambiguity, and unordered iteration in protocol code.

Tests must include deterministic fixtures and negative cases. Security-sensitive code requires readable names, comments explaining invariants, and no hidden fallback that weakens verification. Log identifiers and outcomes, never secrets or protected values unless an explicitly authorized forensic mode is selected.
