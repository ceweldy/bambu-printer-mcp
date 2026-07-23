#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const listed = execFileSync(
  "git",
  ["ls-files", "--cached", "--others", "--exclude-standard", "-z"],
  { cwd: repoRoot }
).toString("utf8");
const files = listed.split("\0").filter(Boolean);

const forbiddenFileExtensions = new Set([
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".pcap",
  ".pcapng",
]);
const allowedEnvironmentFiles = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
]);
const isForbiddenFileName = (baseName) =>
  (baseName.startsWith(".env") && !allowedEnvironmentFiles.has(baseName)) ||
  forbiddenFileExtensions.has(path.extname(baseName));
const contentRules = [
  { label: "private-key material", pattern: /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gu },
  { label: "macOS user path", pattern: /\/Users\/(?!example(?:\/|$)|yourname(?:\/|$))[^/\s]+\//gu },
  { label: "Linux user path", pattern: /\/home\/(?!example(?:\/|$)|yourname(?:\/|$))[^/\s]+\//gu },
  { label: "RFC1918 address", pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/gu },
  {
    label: "private email address",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu,
    allow: (value) =>
      /@users\.noreply\.github\.com$/iu.test(value) ||
      value.toLowerCase() === "noreply@github.com",
  },
];

const findings = [];
for (const relativePath of files) {
  if (relativePath === "scripts/privacy-scan.mjs") continue;
  const absolutePath = path.join(repoRoot, relativePath);
  if (!fs.existsSync(absolutePath)) continue;
  const stat = fs.statSync(absolutePath);
  if (!stat.isFile()) continue;

  const baseName = path.basename(relativePath).toLowerCase();
  if (isForbiddenFileName(baseName)) {
    findings.push({ file: relativePath, rule: "credential or capture filename" });
    continue;
  }

  const buffer = fs.readFileSync(absolutePath);
  if (buffer.includes(0)) continue;
  const text = buffer.toString("utf8");
  for (const rule of contentRules) {
    rule.pattern.lastIndex = 0;
    const matches = [...text.matchAll(rule.pattern)].filter(
      (match) => !rule.allow?.(match[0]),
    );
    if (matches.length > 0) {
      findings.push({ file: relativePath, rule: rule.label });
    }
  }
}

if (findings.length > 0) {
  const showTargets =
    process.env.PRIVACY_SCAN_SHOW_PATHS === "1" && process.env.CI !== "true";
  console.error(`Privacy scan failed with ${findings.length} finding(s):`);
  findings.forEach((finding, index) => {
    const target = showTargets ? ` (${finding.file})` : "";
    console.error(`- finding-${index + 1}: ${finding.rule}${target}`);
  });
  if (!showTargets) {
    console.error(
      "Set PRIVACY_SCAN_SHOW_PATHS=1 outside CI for a local path-level report.",
    );
  }
  process.exit(1);
}

console.log(`Privacy scan passed for ${files.length} publishable files.`);
