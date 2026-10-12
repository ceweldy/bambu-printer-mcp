#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const git = (...args) =>
  execFileSync("git", args, {
    cwd: repoRoot,
    encoding: args[0] === "cat-file" && args[1] === "blob" ? null : "utf8",
    maxBuffer: 64 * 1024 * 1024,
  });

const allowedCommitEmail = (email) =>
  /@users\.noreply\.github\.com$/iu.test(email) ||
  email.toLowerCase() === "noreply@github.com";

const findings = [];
const configuredRevision = process.env.PRIVACY_SCAN_REF?.trim();
const revisionArgs = configuredRevision ? [configuredRevision] : ["--all"];
const skipSyntheticTipMetadata =
  process.env.PRIVACY_SCAN_SKIP_SYNTHETIC_TIP_METADATA === "1";
const metadataRevisionArgs =
  configuredRevision && skipSyntheticTipMetadata
    ? [`${configuredRevision}^@`]
    : revisionArgs;
const commitLines = git(
  "log",
  "--format=%H%x09%ae%x09%ce",
  ...metadataRevisionArgs,
)
  .trim()
  .split(/\r?\n/u)
  .filter(Boolean);

for (const line of commitLines) {
  const [commit, authorEmail, committerEmail] = line.split("\t");
  for (const [role, email] of [
    ["author", authorEmail],
    ["committer", committerEmail],
  ]) {
    if (!allowedCommitEmail(email)) {
      findings.push({
        target: commit.slice(0, 12),
        rule: `private ${role} email metadata`,
      });
    }
  }
}

const allowedEnvironmentFiles = new Set([
  ".env.example",
  ".env.sample",
  ".env.template",
]);
const forbiddenExtensions = new Set([
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".pcap",
  ".pcapng",
  ".kdbx",
  ".mobileprovision",
]);
const isForbiddenPath = (relativePath) => {
  const baseName = path.posix.basename(relativePath).toLowerCase();
  return (
    (baseName.startsWith(".env") && !allowedEnvironmentFiles.has(baseName)) ||
    baseName === "printers.json" ||
    forbiddenExtensions.has(path.posix.extname(baseName))
  );
};
const contentRules = [
  {
    label: "private-key material",
    pattern: /-----BEGIN (?:ENCRYPTED |RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gu,
  },
  {
    label: "macOS user path",
    pattern: /\/Users\/(?!example(?:\/|$)|yourname(?:\/|$))[^/\s]+\//gu,
  },
  {
    label: "Linux user path",
    pattern: /\/home\/(?!example(?:\/|$)|yourname(?:\/|$))[^/\s]+\//gu,
  },
  {
    label: "Windows user path",
    pattern: /[A-Za-z]:\\Users\\(?!example(?:\\|$)|yourname(?:\\|$))[^\\\s]+\\/gu,
  },
  {
    label: "RFC1918 address",
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/gu,
  },
  {
    label: "private email address",
    pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/giu,
    allow: (value) =>
      /@users\.noreply\.github\.com$/iu.test(value) ||
      value.toLowerCase() === "noreply@github.com",
  },
  {
    label: "Bambu serial candidate",
    pattern: /\b(?:00M|00W|01P|01S|030|039|03W|093|094)(?=[A-Z0-9]{8,}\b)(?=[A-Z0-9]*[A-Z])[A-Z0-9]+\b/gu,
    allow: (value) => /(?:TEST|EXAMPLE)/u.test(value),
  },
];

const objectPaths = new Map();
const commits = git("rev-list", ...revisionArgs)
  .trim()
  .split(/\r?\n/u)
  .filter(Boolean);
for (const commit of commits) {
  const tree = git("ls-tree", "-r", "-z", "--full-tree", commit);
  for (const entry of tree.toString("utf8").split("\0").filter(Boolean)) {
    const tab = entry.indexOf("\t");
    if (tab === -1) continue;
    const metadata = entry.slice(0, tab).split(" ");
    const oid = metadata[2];
    const relativePath = entry.slice(tab + 1);
    const paths = objectPaths.get(oid) ?? new Set();
    paths.add(relativePath);
    objectPaths.set(oid, paths);

    if (isForbiddenPath(relativePath)) {
      findings.push({
        target: relativePath,
        rule: "credential or capture filename in history",
      });
    }
  }
}

let blobCount = 0;
for (const [oid, paths] of objectPaths) {
  if (git("cat-file", "-t", oid).trim() !== "blob") continue;
  blobCount += 1;
  const buffer = git("cat-file", "blob", oid);
  const textVariants = [buffer.toString("utf8")];
  if (buffer.includes(0)) {
    textVariants.push(buffer.toString("utf16le"));
    const evenLength = buffer.length - (buffer.length % 2);
    const swapped = Buffer.allocUnsafe(evenLength);
    for (let index = 0; index < evenLength; index += 2) {
      swapped[index] = buffer[index + 1];
      swapped[index + 1] = buffer[index];
    }
    textVariants.push(swapped.toString("utf16le"));
  }

  for (const rule of contentRules) {
    const matched = textVariants.some((text) => {
      rule.pattern.lastIndex = 0;
      return [...text.matchAll(rule.pattern)].some(
        (match) => !rule.allow?.(match[0]),
      );
    });
    if (!matched) continue;
    for (const relativePath of [...paths].sort()) {
      findings.push({ target: relativePath, rule: rule.label });
    }
  }
}

const uniqueFindings = [
  ...new Map(
    findings.map((finding) => [`${finding.target}\0${finding.rule}`, finding]),
  ).values(),
];

if (uniqueFindings.length > 0) {
  const showTargets =
    process.env.PRIVACY_SCAN_SHOW_PATHS === "1" && process.env.CI !== "true";
  console.error(
    `History privacy scan failed with ${uniqueFindings.length} finding(s):`,
  );
  uniqueFindings.forEach((finding, index) => {
    const target = showTargets ? ` (${finding.target})` : "";
    console.error(`- finding-${index + 1}: ${finding.rule}${target}`);
  });
  if (!showTargets) {
    console.error(
      "Set PRIVACY_SCAN_SHOW_PATHS=1 outside CI for a local path-level report.",
    );
  }
  process.exit(1);
}

console.log(
  `History privacy scan passed for ${commitLines.length} commits and ${blobCount} blobs.`,
);
