# Contributing

Contributions are welcome when they preserve hardware safety, privacy, and GPL-2.0 provenance.

Before opening a pull request:

```sh
npm ci
npm run build
npm test
npm audit --omit=dev
npm run privacy:check
npm pack --dry-run
```

Use synthetic fixtures. Do not submit real printer addresses, serials, access codes, account data, screenshots, camera images, captured payloads, or local absolute paths.

Printer-changing behavior requires focused tests and an operator-visible behavior contract.
