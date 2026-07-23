# Repository instructions

## Safety

- Never weaken printer model validation.
- Never add a fleet-wide physical command without an explicit confirmation contract and dedicated tests.
- Never place printer credentials, serials, addresses, camera images, MQTT captures, or operator-specific details in the repository.
- Keep Streamable HTTP loopback-only unless authenticated remote transport is implemented and reviewed.

## Build and validation

- Run `npm run build` and `npm test` after code changes.
- Run `npm audit --omit=dev`, `npm run privacy:check`, and `npm pack --dry-run` before publishing.
- Run the installed AutoReview and behavior-validator workflows after non-trivial behavior changes.
- Tests compile from `src` into `dist` before exercising the server.

## Release

- Do not publish to npm, create a GitHub release, or push a tag unless the user explicitly authorizes that release action.
- Keep `CHANGELOG.md` updated for printer behavior, protocol, security, or release changes.

## Architecture

- Printer communication uses MQTT on 8883 and implicit FTPS on 990.
- Multi-printer metadata belongs in `PrinterRegistry`; credentials remain runtime-only or environment-referenced.
- Printer-changing commands must use the per-printer serialization boundary.
- The project is Bambu-only and does not carry OctoPrint, Klipper, Duet, Repetier, Prusa Connect, or Creality adapters.
