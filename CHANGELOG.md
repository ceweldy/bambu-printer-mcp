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
- Package metadata now points to the public `ceweldy/bambu-printer-mcp` continuation.
- `basic-ftp` and vulnerable transitive dependencies are updated or overridden to patched versions.
- The supported runtime is Node.js 20 or newer to match the secured HTTP adapter.
- npm publication is disabled; releases are installed from the public GitHub source tree.
- Public documentation uses sanitized examples and no operator-specific screenshots.

### Fixed

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
