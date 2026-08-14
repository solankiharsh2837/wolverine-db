# Threat model

Threats: malicious application user; compromised API account; compromised DBA credential; malicious insider; compromised application server; direct PostgreSQL attacker; history modifier; checkpoint manipulator; and compromised recovery operator.

WolverineDB can detect divergence from independently retained commitments and missing or modified recorded material within its configured trust model. It cannot reliably distinguish a fully authorized malicious action from a legitimate one without independent evidence, nor protect secrets or availability by itself. Each deployment must map threats to controls, detection, limitations, and incident response before production use.
