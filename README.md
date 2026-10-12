# Bambu Printer MCP

A privacy-conscious Model Context Protocol server for managing, monitoring, slicing for, and controlling multiple Bambu Lab 3D printers.

This project is an independent GPL-2.0 continuation of [`DMontgomery40/bambu-printer-mcp`](https://github.com/DMontgomery40/bambu-printer-mcp). It keeps the original printer, AMS, 3MF, camera, and slicing capabilities while adding a named multi-printer registry, fleet status, reconnect management, per-printer operation serialization, credential references, and stronger privacy defaults.

It is community software and is not affiliated with or endorsed by Bambu Lab.

## Highlights

- Named profiles for multiple printers
- Explicit printer targeting with safe default selection
- Redacted fleet status with bounded parallel queries
- Per-printer serialization across reads, commands, reconnects, and profile changes
- Runtime-only access tokens or environment-variable references
- Atomic `0600` registry files and `0700` config directories
- MQTT printer status and control
- FTPS upload, listing, and guarded deletion
- AMS inventory, matching, RFID reread, and supported dryer controls
- Camera snapshots for supported printer families
- Bambu Studio and compatible Orca-family slicing workflows
- H2-family 3MF routing and crash-resistant dependency patching
- Stdio and loopback-only Streamable HTTP MCP transports

## Safety model

This server can move hardware, heat components, upload files, and start or stop prints. The following rules are intentional:

- A verified printer model is required for print operations.
- Physical commands target one named printer at a time.
- `all` is limited to fleet status and explicitly confirmed reconnect operations.
- File deletion requires `confirm:true` and is restricted to printer-managed directories.
- Persisted printer profiles may reference identifiers and secrets, but may not contain plaintext serial numbers, device IDs, or access tokens.
- Streamable HTTP is restricted to loopback because the server does not provide remote authentication.

Always check the build plate, nozzle, filament, AMS mapping, and selected printer before starting a job.

## Requirements

- Node.js 20 or newer
- A supported Bambu Lab printer reachable on the same trusted LAN
- LAN Only or Developer Mode as required by the printer firmware
- Bambu Studio only when using local slicing tools
- `ffmpeg` only when using RTSP-based camera snapshots

Supported model identifiers:

`p1s`, `p1p`, `p2s`, `x1c`, `x1e`, `a1`, `a1mini`, `h2d`, `h2s`, `h2c`

## Install

This is a public GitHub project, but it is intentionally not published to npm.
Install from the audited source tree so its dependency overrides and Bambu
compatibility patch are applied exactly as tested.

```sh
git clone https://github.com/ceweldy/bambu-printer-mcp.git
cd bambu-printer-mcp
npm ci
npm test
```

Run the MCP server over stdio:

```sh
npm start
```

## Multi-printer configuration

The default registry path is:

```text
~/.config/bambu-printer-mcp/printers.json
```

The registry stores only nonsecret metadata and environment-variable names. Create it with private permissions:

```sh
mkdir -p ~/.config/bambu-printer-mcp
chmod 700 ~/.config/bambu-printer-mcp
```

Example registry:

```json
{
  "version": 1,
  "defaultPrinter": "shop-p1s",
  "printers": [
    {
      "id": "shop-p1s",
      "name": "Shop P1S",
      "host": "printer-one.local",
      "model": "p1s",
      "serialEnv": "BAMBU_SHOP_P1S_SERIAL",
      "accessTokenEnv": "BAMBU_SHOP_P1S_TOKEN",
      "devIdEnv": "BAMBU_SHOP_P1S_DEVICE_ID",
      "bedType": "textured_plate",
      "nozzleDiameter": "0.4"
    },
    {
      "id": "engineering-x1c",
      "name": "Engineering X1C",
      "host": "printer-two.local",
      "model": "x1c",
      "serialEnv": "BAMBU_ENGINEERING_X1C_SERIAL",
      "accessTokenEnv": "BAMBU_ENGINEERING_X1C_TOKEN",
      "devIdEnv": "BAMBU_ENGINEERING_X1C_DEVICE_ID",
      "bedType": "engineering_plate",
      "nozzleDiameter": "0.4"
    }
  ]
}
```

Then set the referenced values in the private environment used to launch the MCP server. Do not commit them to this repository.

You may select a different registry path with `BAMBU_PRINTERS_FILE`. `BAMBU_PRINTERS_JSON` is also supported for clients that inject a complete private configuration through the process environment.

### Backward-compatible single-printer environment

The original environment variables still work:

```text
PRINTER_HOST
BAMBU_SERIAL
BAMBU_TOKEN
BAMBU_MODEL
BED_TYPE
NOZZLE_DIAMETER
```

Multi-printer configuration is preferred because it avoids repeatedly passing credentials through tool arguments.

### H2 client certificates

H2-family firmware that requires mutual TLS can load a Bambu-issued client
certificate and key from `BAMBU_CLIENT_CERT` and `BAMBU_CLIENT_KEY`. When those
variables are omitted, the server checks these private standard paths:

```text
~/.config/bambu-printer-mcp/client.crt
~/.config/bambu-printer-mcp/client.key
```

Set the key file to mode `0600`. Both files must exist as a pair. No certificate
or key material belongs in the repository.

Version 2.0 automatically migrates the legacy
`~/Desktop/bambu certs/embedded-cert.pem` and `embedded-key.pem` pair into the
private standard paths. The current process can still use the legacy pair if
that migration cannot be completed.

## MCP client configuration

Build the project first, then configure your MCP client to run the compiled entry point. Replace the path with the private local checkout path on that machine.

```json
{
  "mcpServers": {
    "bambu-printers": {
      "command": "node",
      "args": ["/absolute/path/to/bambu-printer-mcp/dist/index.js"],
      "env": {
        "BAMBU_PRINTERS_FILE": "/absolute/path/to/private/printers.json",
        "BAMBU_SHOP_P1S_SERIAL": "set-in-private-client-config",
        "BAMBU_SHOP_P1S_TOKEN": "set-in-private-client-config",
        "BAMBU_SHOP_P1S_DEVICE_ID": "set-in-private-client-config",
        "BAMBU_ENGINEERING_X1C_SERIAL": "set-in-private-client-config",
        "BAMBU_ENGINEERING_X1C_TOKEN": "set-in-private-client-config",
        "BAMBU_ENGINEERING_X1C_DEVICE_ID": "set-in-private-client-config"
      }
    }
  }
}
```

## Fleet tools

| Tool | Purpose |
| --- | --- |
| `list_printers` | List redacted profile summaries and readiness |
| `add_printer` | Add an in-memory profile or persist safe metadata references |
| `remove_printer` | Remove a profile after `confirm:true` |
| `set_default_printer` | Select the implicit target |
| `get_fleet_status` | Query every ready printer with bounded concurrency |
| `reconnect_printer` | Reconnect one printer or an explicitly confirmed fleet |

Every printer-specific tool accepts a `printer` field containing the configured ID. If it is omitted, the registry uses the configured default or automatically selects the only configured printer. When multiple printers exist without a default, the call fails and lists the valid IDs.

Example operator requests:

```text
List my configured printers.
Get fleet status.
Show AMS inventory for printer shop-p1s.
Capture a camera snapshot from engineering-x1c.
Pause the current job on shop-p1s.
```

## Core printer capabilities

The server includes tools for:

- printer status, HMS diagnostics, temperatures, print progress, and AMS data
- printer file listing, uploads, guarded deletion, and print start
- pause, resume, cancel, speed, fan, light, temperature, airduct, and object-skip commands
- AMS filament inventory, automatic 3MF-to-AMS matching, RFID reread, and drying controls
- chamber-camera JPEG snapshots
- STL inspection and transformations
- Bambu Studio and compatible Orca-family slicing
- pre-sliced `.gcode.3mf` printing with plate and AMS mapping controls
- optional BambuNetwork bridge workflows

Use `tools/list` from an MCP client for the authoritative schema and descriptions.

## BambuNetwork bridge printing

The optional BambuNetwork path now performs the same LAN startup gates as the
slicer:

1. Stage `slicer_base64.cer` and `printer.cer` into the private MCP config
   directory.
2. Initialize the certificate directory before starting the network agent.
3. Connect the selected printer over LAN MQTT and wait for its
   `on_local_connect` success callback.
4. Dispatch the device-certificate refresh request.
5. Verify that the host and plugin advertise exact sequence correlation before
   uploading anything.
6. Upload the 3MF under a stable remote filename, publish `project_file` with a
   bounded per-submission status marker, and wait for the response carrying
   that command's exact `sequence_id`.
7. Confirm through accumulated differential `push_status` reports that the exact job
   entered PREPARE or RUNNING before reporting success.

Use `bambu_network_bridge_status` with `probe_printer:true` to test steps 1
through 4 without uploading or starting a print. A P1S local print defaults to
the firmware-required `sdcard/` FTP folder.

The raw `bambu_network_call` tool remains available for diagnostics and control
replies. Connection, certificate, and print-start methods are reserved for the
guarded readiness and print tools so callers cannot bypass their lifecycle.

The upstream `install_device_cert` ABI is void, so the bridge can confirm only
that the refresh request was dispatched. LAN readiness is based on the observed
TLS/MQTT connection callback, not an unobservable certificate-snapshot result.

The open `open-bambu-networking` replacement requires Developer Mode for LAN
printing on current signed-command firmware. If the printer returns error
`84033543`, the MCP reports command verification failure instead of claiming
the print started. Enable Developer Mode on the printer, then repeat the
non-print probe before sending the job.

The FULU proprietary Linux bridge remains experimental. Its published host
dispatches plugin calls on detached threads, which can terminate the host during
LAN setup. Use a host build that sends ordinary plugin RPC calls through one
worker while keeping polling, wait replies, and cancellation available to an
in-flight job. The minimal host-side change is included as
[`docs/patches/fulu-linux-host-serialize-rpc.patch`](docs/patches/fulu-linux-host-serialize-rpc.patch).

Exact acknowledgement correlation also requires the bridge host to return the
sequence generated by the open plugin. Apply both
[`docs/patches/open-bambu-networking-project-file-sequence.patch`](docs/patches/open-bambu-networking-project-file-sequence.patch)
to `open-bambu-networking` and
[`docs/patches/fulu-linux-host-project-file-sequence.patch`](docs/patches/fulu-linux-host-project-file-sequence.patch)
to the FULU host source before building those runtimes. The MCP fails closed
before upload when an older runtime does not advertise this value, instead of
accepting a stale printer response or submitting an unconfirmable job. The open
plugin patch also keeps the remote archive filename stable while using the
unique marker only for status correlation.

## MCP resources

Configured printers are exposed by stable ID instead of IP address:

```text
fleet://status
printer://shop-p1s/status
printer://shop-p1s/files
printer://shop-p1s/hms
```

Resource listings never include printer IPs, serial numbers, or access tokens.

### Version 2.0 resource migration

Version 2.0 intentionally replaces legacy host-based resource URIs with
profile IDs. Update `printer://<host>/...` consumers to
`printer://<printer-id>/...`. Host aliases are not retained because combining
caller-selected endpoints with stored credentials would weaken profile
isolation.

## Transports

Stdio is the default and recommended transport.

For local Streamable HTTP:

```sh
MCP_TRANSPORT=streamable-http \
MCP_HTTP_HOST=127.0.0.1 \
MCP_HTTP_PORT=3000 \
MCP_HTTP_PATH=/mcp \
npm start
```

Only loopback hosts are accepted. Use a separately authenticated gateway if remote access is required.

## Printer communication

- MQTT over TLS on printer port 8883 carries status and control commands.
- Implicit FTPS on printer port 990 handles file operations.
- Some camera families use TLS port 6000; others use RTSPS with `ffmpeg`.

Bambu printers commonly use self-signed local certificates, so the current printer transports do not perform public-CA verification. Keep printers and this MCP process on a trusted LAN or isolated VLAN. Do not expose printer ports to the public internet.

## H2-family behavior

The upstream `bambu-node` dependency does not natively identify every H2 model and can throw from an asynchronous MQTT listener. This project carries a `patch-package` patch that:

- preserves the configured model for unknown OTA serial prefixes
- treats missing OTA model metadata as recoverable
- treats unusual printer state transitions as recoverable instead of terminating the MCP process

Regression tests exercise those event paths after every install.

## Validation order for a real printer

Use this order when connecting a new printer:

1. `list_printers`
2. `get_printer_status`
3. HMS and AMS reads
4. file listing
5. camera snapshot
6. disconnect and reconnect
7. upload a known harmless file without printing
8. physical controls only when the operator can observe the printer
9. print start only with a verified plate, nozzle, material, model, and AMS mapping

Automated tests never start a real print.

### Verified hardware coverage

The multi-printer release has been exercised against P1S and A1 hardware on a
local network. Status, fleet status, HMS diagnostics, AMS inventory, FTPS file
listing, disconnect, reconnect, and post-reconnect status were verified through
the packaged MCP interface. That validation did not start, pause, resume, or
cancel a print, move an axis, change a heater, or upload a file.

## Development

```sh
npm ci
npm run build
npm test
npm audit --omit=dev
npm run privacy:check
npm pack --dry-run
```

CI runs the same build, test, dependency-audit, package, and privacy gates.

## Privacy

Do not commit:

- printer IP addresses or private hostnames
- serial numbers, LAN access codes, cloud credentials, or tokens
- Wi-Fi information or network screenshots
- camera images or MQTT captures
- operator names or printer nicknames
- local absolute paths, logs, `.env` files, certificates, or private keys

The first public history of this repository is a sanitized snapshot. Earlier upstream history remains available from the attributed upstream repository but is intentionally not mirrored here.

## License and provenance

GPL-2.0. See [LICENSE](LICENSE) and [UPSTREAM.md](UPSTREAM.md).
