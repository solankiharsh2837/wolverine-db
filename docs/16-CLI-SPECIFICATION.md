# CLI specification

Commands: `wdb init`, `status`, `verify`, `history`, `diff`, `checkpoint`, `anchor`, `inspect`, and `recover`. Every command supports a human-readable report and `--json` machine output; exit codes distinguish valid, invalid, indeterminate, configuration, and operational failures.

`wdb recover` defaults to plan generation. Commit requires an explicit approval reference and confirmation mechanism defined by policy. Configuration file discovery, credential sources, and final exit-code numbers are **UNRESOLVED**.
