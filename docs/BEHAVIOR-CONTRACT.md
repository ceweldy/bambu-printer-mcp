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
18. The BambuNetwork bridge can stage its public certificate bundle and complete
    a LAN MQTT readiness probe without uploading a file or starting a print.
    Both certificate files come from one complete source directory, and an
    incomplete explicitly configured bundle fails closed without replacing the
    previously staged bundle.
19. The LAN bridge does not submit a print until the selected printer reports a
    successful local connection callback.
20. A BambuNetwork local print does not report success until the printer
    responds to `project_file` with the exact submitted sequence ID and a
    separate live `push_status` report confirms the exact submitted job entered
    PREPARE or RUNNING.
21. A printer response with error `84033543` is surfaced as an MQTT command
    verification failure with Developer Mode or authenticated stock-plugin
    guidance, and the printer remains idle.
22. A delayed `project_file` response from an earlier submission cannot approve
    or reject the current submission.
23. Each submission uses a server-generated marker in every status-visible
    project and task name, even when a caller reuses its own job ID or task
    name.
24. Event polling, callback replies, wait replies, and cancellation remain
    available while a managed BambuNetwork print owns the serialized lifecycle.
    Acknowledgement and job-start waiters preserve unrelated events for the
    control polling lane.
25. A stale status snapshot for another job is ignored while the MCP waits for
    the exact current submission.
26. A local print fails before upload when the host and plugin do not advertise
    exact `project_file` sequence correlation.
27. Retries reuse a stable remote archive filename while each status-visible
    submission marker remains unique, valid UTF-8, and bounded to 96 bytes.
28. Differential P1/P1S status reports can provide the exact job name and a
    later active state in separate messages without causing a false timeout.
    A job-name change clears any state inherited from a prior or unknown job.
    PAUSE and PAUSED do not prove that the exact job entered PREPARE or RUNNING.
29. The public print tools do not expose `start_local_print_with_record`
    because that bridge method cannot provide the exact `project_file`
    acknowledgement required for guarded local-print success.

Live clauses are blocked, not failed, when the operator has no reachable printer
or private credentials available. Validation never starts, pauses, resumes, or
cancels a print.
