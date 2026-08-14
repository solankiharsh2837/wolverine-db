# Error model

Errors use stable codes: `WDB1xx` protocol/serialization, `WDB2xx` database, `WDB3xx` integrity/Merkle, `WDB4xx` anchor, `WDB5xx` recovery, `WDB6xx` authorization, and `WDB7xx` configuration.

Every error has code, safe message, operation identifier, retryability, and cause category. Reports must never leak values, credentials, or protected metadata by default. Exact code allocation is **UNRESOLVED**, but codes must be additive and documented before public release.
