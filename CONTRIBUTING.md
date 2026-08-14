# Contributing

WolverineDB is security-sensitive. Start every change by reading `prompts/AGENTS.md`. Protocol, serialization, cryptography, authorization, and recovery changes require a written specification update, test vectors, and review before implementation.

## Contribution rules

1. Keep committed history immutable; fixes are new records and versions.
2. Do not claim that a mismatch proves malicious intent.
3. Add deterministic tests for every public behavior and negative tests for every security boundary.
4. Keep implementation choices explicitly marked until frozen in `specs/`.
5. Submit small changes with a threat and compatibility impact statement.

Do not submit secrets, production data, or security vulnerabilities in public issues.
