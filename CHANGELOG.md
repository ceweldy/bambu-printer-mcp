# Changelog

## Unreleased

### Added

- Named multi-printer registry with default selection and explicit printer targeting.
- Redacted `list_printers` and failure-isolated `get_fleet_status` tools.
- Safe add, remove, default, and reconnect management tools.
- Atomic private registry persistence using environment-variable secret references.
- Per-printer serialization for hardware-changing commands.
- H2-family regression coverage for asynchronous model and state messages.
- CI, dependency auditing, packaging validation, and repository privacy scanning.
- Full-history privacy validation for committed paths, content, and commit email
  metadata.

### Changed

- MCP resources use configured printer IDs instead of LAN addresses.
- BambuStudio CLI profile flattening is enabled by default, with an explicit
  `BAMBU_CLI_FLATTEN=0` escape hatch for diagnostics.
- P1/A1/X1 local `project_file` commands use firmware-safe `bed_type: auto`
  metadata, right-align the fixed five-entry AMS mapping, and wait for an
  explicit printer acknowledgement before reporting success.
- Package metadata now points to the public `ceweldy/bambu-printer-mcp` continuation.
- `basic-ftp` and vulnerable transitive dependencies are updated or overridden to patched versions.
- The supported runtime is Node.js 20 or newer to match the secured HTTP adapter.
- npm publication is disabled; releases are installed from the public GitHub source tree.
- Public documentation uses sanitized examples and no operator-specific screenshots.

### Fixed

- Nested vendor filament profiles, including SUNLU profiles, now resolve their
  full inheritance chain instead of silently falling back to PLA metadata.
- SuperTack raw-STL slices use a validated High Temp Plate CLI fallback, then
  rewrite the finished 3MF with the used filaments' initial and steady
  SuperTack temperatures, consistent project and per-plate metadata, G-code
  hash, and archive checks.
- BambuStudio output is checked for requested filament, preset, printable
  G-code, and plate consistency before a sliced 3MF is returned.
- Negative or missing `project_file` acknowledgements are surfaced as failures
  instead of returning a false "sent successfully" result. Result-less local
  command echoes are ignored until the printer replies or enters an active state.
- Idle printers can reset and resume an incomplete AMS load or unload operation
  through the dedicated `reset_ams` recovery tool.
- Idle printers can explicitly load a validated absolute AMS slot at a bounded
  nozzle temperature through `load_ams_filament`.
- Idle printers can complete an acknowledged AMS unload through
  `unload_ams_filament`.
- Idle printers can be restarted through `reboot_printer`; active print states
  and unknown printer states are rejected before the system reboot command is
  sent.
- FTPS uploads allow a bounded 60-second data-channel window and a longer TLS
  session-ticket wait for printers whose file service recovers slowly after reboot.
- Post-January 2025 firmware `print.*` commands are wrapped in canonical
  RSA-SHA256 signed envelopes using the configured Bambu client certificate,
  while G-code-line encryption is gated to printer families known to require it.
- Printer access tokens are fingerprinted rather than embedded in internal connection-map keys.
- Unknown printer model metadata and unusual status transitions no longer terminate the process.
- Initial fleet and reconnect responses wait for the first operational status
  packet instead of returning a transient `UNKNOWN` state from a sparse startup
  packet.
- The test suite uses an isolated empty registry, so a developer's private
  printer configuration cannot change public test results.

### Removed

- Operator-specific deployment notes, live printer probes, names, addresses, serial examples, and screenshots from the publishable tree.
- Operator-specific compatibility tools, fixture metadata, and host-based
  resource aliases. Version 2.0 uses the generic 3MF and AMS tools plus
  profile-ID resources.

## 1.1.5 upstream baseline

The sanitized continuation began from upstream commit `a7a4444b413beb9d343b9ff3544e112b3ffe67af`. See [UPSTREAM.md](UPSTREAM.md) for provenance.
