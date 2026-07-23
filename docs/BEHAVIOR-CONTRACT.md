# Behavior Contract

This contract defines the public, operator-visible behavior required for the
2.0 multi-printer release. Validation must use a built package or running MCP
server without reading its source during the validation pass.

## Synthetic fleet behavior

1. The packaged server starts over stdio, identifies itself as version 2.0.0,
   and exposes the fleet-management tools.
2. Two synthetic printer profiles can be loaded from environment configuration.
3. Printer listings contain stable IDs, models, readiness, and default state,
   but never expose hostnames, serial numbers, or access tokens.
4. Multiple printers without a default require an explicit printer target.
5. Setting a default printer makes an omitted target resolve unambiguously.
6. A persisted profile references identifier and credential environment
   variables, uses private directory and file permissions, and never writes a
   plaintext serial number, BambuNetwork device ID, or access token.
7. Streamable HTTP starts on a loopback address and refuses a non-loopback bind.
8. Unknown H2-family OTA metadata and unusual state transitions do not terminate
   the server process.
9. The packed artifact and repository privacy checks contain no operator
   paths, private network addresses, credentials, private keys, or personal
   printer identifiers.
10. Selecting a configured printer cannot be combined with a different host,
    serial number, access token, device ID, or model.
11. Fleet and reconnect errors expose a stable category without returning a
    printer endpoint or credential value.
12. Local slicing remains usable when a fleet has multiple printers and no
    default, unless the caller explicitly selects a printer for its defaults.
13. The reserved `all` target cannot be registered as a printer profile.
14. The source tree refuses npm publication and declares Node.js 20 or newer.

## Live printer behavior

15. With private credentials supplied outside the repository, the server can
    connect to a configured Bambu Lab printer and return a status response.
16. Read-only diagnostics available for that printer can be queried without
    initiating a print, moving an axis, or changing a heater.
17. A reconnect restores the status path after disconnecting the MCP-side
    client and returns an operational printer state rather than a transient
    sparse-packet `UNKNOWN` state. It must not alter an active print job.

Live clauses are blocked, not failed, when the operator has no reachable printer
or private credentials available. Validation never starts, pauses, resumes, or
cancels a print.
