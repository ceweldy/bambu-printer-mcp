# Security policy

## Reporting

Use GitHub private vulnerability reporting for security issues. Do not include real printer credentials, serial numbers, LAN addresses, camera images, or captured payloads in a public issue.

## Trust boundary

This software controls physical equipment over a local network. Run it only on a trusted host and network. Do not expose printer MQTT, FTPS, camera ports, or the MCP server directly to the public internet.

Streamable HTTP is intentionally loopback-only. Stdio is recommended.

## Credentials

- Keep access tokens in a private MCP client configuration, secret manager, or process environment.
- Persisted fleet profiles may contain environment-variable names but not plaintext serial numbers, device IDs, or access tokens.
- Rotate a printer LAN access code if it appears in logs, screenshots, shell history, issues, or commits.
- Never commit `.env`, certificate, key, registry, or captured printer files.
- Store an H2 client key at mode `0600`, either at the documented private
  config path or at the path named by `BAMBU_CLIENT_KEY`.

## Physical safety

Verify the selected printer, model, nozzle, plate, material, file, and AMS mapping before starting a print. Treat every control-capable MCP client as privileged software.
