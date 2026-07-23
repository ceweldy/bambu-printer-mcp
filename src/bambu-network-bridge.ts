import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const FRAME_MAGIC = 0x52424a50;
const FRAME_HEADER_SIZE = 16;
const FRAME_TYPE_JSON_REQUEST = 1;
const FRAME_TYPE_JSON_RESPONSE = 2;
const FRAME_TYPE_BINARY_DATA = 3;
const FRAME_TYPE_LOG = 4;
const DEFAULT_REQUEST_TIMEOUT_MS = 120_000;

type JsonObject = Record<string, unknown>;

type PendingRequest = {
  method: string;
  resolve: (value: unknown) => void;
  reject: (error: Error) => void;
  timer: NodeJS.Timeout;
};

export type BambuNetworkBridgeOptions = {
  bridgeCommand?: string;
  configDir?: string;
  certDir?: string;
  countryCode?: string;
  userInfo?: string;
  timeoutMs?: number;
  confirmationTimeoutMs?: number;
};

export type BambuNetworkBridgeStatus = {
  configured: boolean;
  command: string;
  platform: NodeJS.Platform;
  running: boolean;
  pid?: number;
  configDir: string;
  countryCode: string;
  agentReady: boolean;
  lastStderr: string;
  recentLogs: string[];
  runtime: {
    macosRuntimeDir: string;
    macosRuntimeDirExists: boolean;
    macosPluginDir?: string;
    macosPluginDirExists?: boolean;
    macosMissingRuntimeFiles: string[];
    macosMissingPluginFiles: string[];
    suggestedMacCommand?: string;
  };
  note?: string;
};

export function defaultBambuNetworkConfigDir(): string {
  return path.join(os.homedir(), ".config", "bambu-printer-mcp", "bambu-network");
}

const BAMBU_NETWORK_CERT_FILES = [
  "slicer_base64.cer",
  "printer.cer",
] as const;
const BAMBU_NETWORK_PROJECT_FILE_METHODS = new Set([
  "start_local_print",
  "start_sdcard_print",
]);
const MANAGED_BAMBU_NETWORK_CALL_METHODS = new Set([
  "net.create_agent",
  "net.destroy_agent",
  "net.set_config_dir",
  "net.set_cert_file",
  "net.start",
  "net.stop",
  "net.connect_printer",
  "net.disconnect_printer",
  "net.install_device_cert",
  "net.send_message",
  "net.send_message_to_printer",
  "net.start_print",
  "net.start_local_print",
  "net.start_local_print_with_record",
  "net.start_send_gcode_to_sdcard",
  "net.start_sdcard_print",
]);
const BAMBU_NETWORK_CONTROL_METHODS = new Set([
  "bridge.poll_events",
  "bridge.job_wait_reply",
  "bridge.job_cancel",
  "bridge.callback_reply",
  "ft.job_cancel",
]);

export function requiresBambuNetworkProjectFileAcknowledgement(method: string): boolean {
  return BAMBU_NETWORK_PROJECT_FILE_METHODS.has(method);
}

export function isManagedBambuNetworkCallMethod(method: string): boolean {
  return MANAGED_BAMBU_NETWORK_CALL_METHODS.has(method);
}

export function isBambuNetworkControlMethod(method: string): boolean {
  return BAMBU_NETWORK_CONTROL_METHODS.has(method);
}

export function requiresBambuNetworkAgentForRawCall(
  method: string,
  withAgent: boolean | undefined
): boolean {
  return withAgent !== false && !isBambuNetworkControlMethod(method);
}

export function createBambuNetworkSubmissionNames(
  projectName: string,
  taskName?: string
): { projectName: string; taskName: string; nonce: string } {
  const nonce = randomUUID().replace(/-/g, "").slice(0, 12);
  const marker = `__mcp_${nonce}`;
  const maxNameBytes = 96;
  const maxPrefixBytes = maxNameBytes - Buffer.byteLength(marker, "utf8");
  const mark = (value: string): string => {
    const validUtf8Value = Buffer.from(value, "utf8").toString("utf8");
    let prefix = "";
    let prefixBytes = 0;
    for (const character of validUtf8Value) {
      const characterBytes = Buffer.byteLength(character, "utf8");
      if (prefixBytes + characterBytes > maxPrefixBytes) {
        break;
      }
      prefix += character;
      prefixBytes += characterBytes;
    }
    return `${prefix}${marker}`;
  };
  return {
    projectName: mark(projectName),
    taskName: mark(taskName || projectName),
    nonce,
  };
}

export function stageBambuNetworkCertificates(
  configDir: string,
  sourceDirectories: string[],
  strictSourceDirectory?: string
): { certDir?: string; missing: string[]; fingerprint?: string } {
  const certDir = path.join(configDir, "cert");
  const lockDir = path.join(configDir, ".cert-stage.lock");
  const lockDeadline = Date.now() + 10_000;
  const lockWait = new Int32Array(new SharedArrayBuffer(4));
  fs.mkdirSync(configDir, { recursive: true });
  while (true) {
    try {
      fs.mkdirSync(lockDir);
      break;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code !== "EEXIST") {
        throw error;
      }
      try {
        if (Date.now() - fs.statSync(lockDir).mtimeMs > 30_000) {
          fs.rmSync(lockDir, { recursive: true, force: true });
          continue;
        }
      } catch {
        continue;
      }
      if (Date.now() >= lockDeadline) {
        throw new Error(
          `Timed out waiting to stage the BambuNetwork certificate bundle in ${configDir}.`
        );
      }
      Atomics.wait(lockWait, 0, 0, 25);
    }
  }

  try {
    const missingFrom = (directory: string): string[] =>
      BAMBU_NETWORK_CERT_FILES.filter(
        (filename) => !fileExists(path.join(directory, filename))
      );
    const fingerprintDirectory = (directory: string): string => {
      const fingerprint = createHash("sha256");
      for (const filename of BAMBU_NETWORK_CERT_FILES) {
        fingerprint.update(filename);
        fingerprint.update(fs.readFileSync(path.join(directory, filename)));
      }
      return fingerprint.digest("hex");
    };
    const strictSource = trimEnv(strictSourceDirectory);
    if (strictSource) {
      const missing = missingFrom(strictSource);
      if (missing.length > 0) {
        return { certDir: undefined, missing };
      }
    }

    const sourceDir =
      strictSource ||
      sourceDirectories.find((directory) => missingFrom(directory).length === 0) ||
      (missingFrom(certDir).length === 0 ? certDir : undefined);
    if (!sourceDir) {
      const partialSource = sourceDirectories.find(
        (directory) => missingFrom(directory).length < BAMBU_NETWORK_CERT_FILES.length
      );
      const missing = partialSource
        ? missingFrom(partialSource)
        : [...BAMBU_NETWORK_CERT_FILES];
      return { certDir: undefined, missing };
    }

    const sourceFingerprint = fingerprintDirectory(sourceDir);
    const stagedFingerprint =
      missingFrom(certDir).length === 0
        ? fingerprintDirectory(certDir)
        : undefined;
    if (
      path.resolve(sourceDir) !== path.resolve(certDir) &&
      sourceFingerprint !== stagedFingerprint
    ) {
      const stagingDir = fs.mkdtempSync(path.join(configDir, ".cert-stage-"));
      const backupDir = path.join(configDir, `.cert-backup-${randomUUID()}`);
      try {
        for (const filename of BAMBU_NETWORK_CERT_FILES) {
          fs.copyFileSync(
            path.join(sourceDir, filename),
            path.join(stagingDir, filename)
          );
        }
        if (fileExists(certDir)) {
          fs.renameSync(certDir, backupDir);
        }
        fs.renameSync(stagingDir, certDir);
        fs.rmSync(backupDir, { recursive: true, force: true });
      } catch (error) {
        if (!fileExists(certDir) && fileExists(backupDir)) {
          fs.renameSync(backupDir, certDir);
        }
        fs.rmSync(stagingDir, { recursive: true, force: true });
        throw error;
      }
    }

    return {
      certDir,
      missing: [],
      fingerprint: fingerprintDirectory(certDir),
    };
  } finally {
    fs.rmSync(lockDir, { recursive: true, force: true });
  }
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function trimEnv(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}

function fileExists(filePath: string): boolean {
  try {
    return fs.existsSync(filePath);
  } catch {
    return false;
  }
}

function resolveFirstExistingDirectory(candidates: string[]): string | undefined {
  return candidates.find((candidate) => fileExists(candidate) && fs.statSync(candidate).isDirectory());
}

function resolveFirstDirectoryWithFile(candidates: string[], requiredFile: string): string | undefined {
  return candidates.find(
    (candidate) =>
      fileExists(candidate) &&
      fs.statSync(candidate).isDirectory() &&
      fileExists(path.join(candidate, requiredFile))
  );
}

function collectMissingFiles(baseDir: string | undefined, files: string[]): string[] {
  if (!baseDir) return files;
  return files.filter((file) => !fileExists(path.join(baseDir, file)));
}

function readFrameJson(payload: Buffer): unknown {
  const text = payload.toString("utf8");
  return text.length > 0 ? JSON.parse(text) : {};
}

function isBridgeFailure(value: unknown): value is { ok: false; error?: unknown } {
  return (
    typeof value === "object" &&
    value !== null &&
    (value as { ok?: unknown }).ok === false
  );
}

function bridgeValueAsNumber(value: unknown, method: string): number {
  if (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { value?: unknown }).value === "number"
  ) {
    return (value as { value: number }).value;
  }

  throw new Error(`FULU BambuNetwork bridge method ${method} did not return a numeric value.`);
}

function assertBridgeOk(value: unknown, method: string): void {
  if (isBridgeFailure(value)) {
    const errorText = value.error === undefined ? "unknown bridge error" : String(value.error);
    throw new Error(`FULU BambuNetwork bridge method ${method} failed: ${errorText}`);
  }
}

export function redactBambuNetworkDiagnostic(message: string): string {
  return message.replace(/\[PJBRIDGE\][^\r\n]*/g, (line) => {
    const kind = line.match(/"kind":"([^"]+)"/)?.[1] || "diagnostic";
    return `[PJBRIDGE] {"kind":"${kind}","payload":"[redacted]"}`;
  });
}

export class BambuNetworkBridge {
  private child?: ChildProcessWithoutNullStreams;
  private commandLine?: string;
  private stdoutBuffer = Buffer.alloc(0);
  private pending = new Map<number, PendingRequest>();
  private nextRequestId = 1;
  private agentId?: number;
  private agentKey?: string;
  private handshake?: unknown;
  private lastStderr = "";
  private recentLogs: string[] = [];
  private inferredExpectedNetworkVersion?: string;
  private agentCertDir?: string;
  private lifecycleTail: Promise<void> = Promise.resolve();
  private agentInitializationTail: Promise<void> = Promise.resolve();
  private preservedEvents: unknown[] = [];
  private preservedControlEvents: unknown[] = [];
  private rawControlLaneOpen = false;

  private preserveEvents(events: unknown[]): void {
    const managedEvents = events.filter(
      (event) =>
        typeof event === "object" &&
        event !== null &&
        ["on_local_connect", "on_local_message"].includes(
          String((event as { name?: unknown }).name || "")
        )
    );
    if (managedEvents.length === 0) return;
    this.preservedEvents.push(...managedEvents);
    if (this.preservedEvents.length > 256) {
      this.preservedEvents.splice(0, this.preservedEvents.length - 256);
    }
  }

  private preserveControlEvents(events: unknown[]): void {
    if (events.length === 0) return;
    this.preservedControlEvents.push(...events);
    if (this.preservedControlEvents.length > 256) {
      this.preservedControlEvents.splice(
        0,
        this.preservedControlEvents.length - 256
      );
    }
  }

  async withExclusiveLifecycle<T>(
    operation: () => Promise<T>,
    options: { allowRawControl?: boolean } = {}
  ): Promise<T> {
    const previous = this.lifecycleTail;
    let release!: () => void;
    this.lifecycleTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    this.rawControlLaneOpen = Boolean(options.allowRawControl);
    try {
      return await operation();
    } finally {
      this.rawControlLaneOpen = false;
      release();
    }
  }

  isRawControlLaneOpen(): boolean {
    return this.rawControlLaneOpen;
  }

  supportsProjectFileSequenceCorrelation(): boolean {
    return (
      typeof this.handshake === "object" &&
      this.handshake !== null &&
      (this.handshake as { project_file_sequence_id?: unknown })
        .project_file_sequence_id === true
    );
  }

  private async withAgentInitialization<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.agentInitializationTail;
    let release!: () => void;
    this.agentInitializationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return await operation();
    } finally {
      release();
    }
  }

  resolveBridgeCommand(override?: string): string {
    return (
      trimEnv(override) ||
      trimEnv(process.env.BAMBU_NETWORK_BRIDGE_COMMAND) ||
      trimEnv(process.env.FULU_BAMBU_NETWORK_BRIDGE_COMMAND) ||
      trimEnv(process.env.PJARCZAK_BAMBU_BRIDGE_COMMAND) ||
      ""
    );
  }

  resolveConfigDir(override?: string): string {
    return (
      trimEnv(override) ||
      trimEnv(process.env.BAMBU_NETWORK_CONFIG_DIR) ||
      trimEnv(process.env.PJARCZAK_BAMBU_PROBE_LOG_DIR) ||
      defaultBambuNetworkConfigDir()
    );
  }

  resolveCountryCode(override?: string): string {
    return (
      trimEnv(override) ||
      trimEnv(process.env.BAMBU_NETWORK_COUNTRY_CODE) ||
      trimEnv(process.env.PJARCZAK_BAMBU_COUNTRY_CODE) ||
      "US"
    );
  }

  private resolveCertificateSources(options: BambuNetworkBridgeOptions): {
    directories: string[];
    strictDirectory?: string;
  } {
    const strictDirectory =
      trimEnv(options.certDir) ||
      trimEnv(process.env.BAMBU_NETWORK_CERT_DIR);
    const runtimeDirectories = [
      trimEnv(process.env.PJARCZAK_MAC_RUNTIME_DIR),
      trimEnv(process.env.PJARCZAK_BAMBU_PLUGIN_DIR),
    ].filter((value): value is string => Boolean(value));

    let conventional: string[];
    if (process.platform === "darwin") {
      conventional = [
          path.join(os.homedir(), "Library", "Application Support", "OrcaSlicer", "macos-bridge", "runtime"),
          "/Applications/BambuStudio.app/Contents/Resources/cert",
          "/Applications/Orca Studio.app/Contents/Resources/cert",
          "/Applications/OrcaSlicer.app/Contents/Resources/cert",
        ];
    } else if (process.platform === "win32") {
      const programRoots = [
        trimEnv(process.env.ProgramFiles),
        trimEnv(process.env["ProgramFiles(x86)"]),
        trimEnv(process.env.LOCALAPPDATA)
          ? path.join(trimEnv(process.env.LOCALAPPDATA)!, "Programs")
          : undefined,
      ].filter((value): value is string => Boolean(value));
      conventional = programRoots.flatMap((root) => [
        path.join(root, "Bambu Studio", "resources", "cert"),
        path.join(root, "OrcaSlicer", "resources", "cert"),
        path.join(root, "Orca Slicer", "resources", "cert"),
      ]);
    } else {
      conventional = [
          "/usr/share/bambu-studio/resources/cert",
          "/usr/share/orca-slicer/resources/cert",
          "/usr/local/share/bambu-studio/resources/cert",
        ];
    }

    return {
      directories: [
        ...new Set(
          [
            strictDirectory,
            ...runtimeDirectories,
            ...conventional,
          ].filter((value): value is string => Boolean(value))
        ),
      ],
      strictDirectory,
    };
  }

  getStatus(options: BambuNetworkBridgeOptions = {}): BambuNetworkBridgeStatus {
    const command = this.resolveBridgeCommand(options.bridgeCommand);
    const configDir = this.resolveConfigDir(options.configDir);
    const countryCode = this.resolveCountryCode(options.countryCode);

    const macosRuntimeDir =
      trimEnv(process.env.PJARCZAK_MAC_RUNTIME_DIR) ||
      path.join(os.homedir(), "Library", "Application Support", "OrcaSlicer", "macos-bridge", "runtime");
    const macosPluginDir =
      trimEnv(process.env.BAMBU_NETWORK_PLUGIN_DIR) ||
      trimEnv(process.env.PJARCZAK_BAMBU_PLUGIN_DIR) ||
      resolveFirstDirectoryWithFile([
        path.join(os.homedir(), "Library", "Application Support", "OrcaSlicer", "plugins"),
        "/Applications/Orca Studio.app/Contents/MacOS",
        "/Applications/OrcaSlicer.app/Contents/MacOS",
        "/Applications/OrcaSlicer-BMCU.app/Contents/MacOS",
        "/Applications/Orca Studio.app/Contents/Resources",
        "/Applications/OrcaSlicer.app/Contents/Resources",
        "/Applications/OrcaSlicer-BMCU.app/Contents/Resources",
        macosRuntimeDir,
      ], "pjarczak-bambu-linux-host-wrapper") ||
      resolveFirstExistingDirectory([macosRuntimeDir]);

    const runtimeRequiredFiles = [
      "libbambu_networking.so",
      "libBambuSource.so",
      "pjarczak_bambu_linux_host",
      "pjarczak_bambu_linux_host_abi1",
      "pjarczak_bambu_linux_host_abi0",
      "ca-certificates.crt",
      "slicer_base64.cer",
      "printer.cer",
    ];
    const pluginRequiredFiles = [
      "pjarczak-bambu-linux-host-wrapper",
      "install_runtime_macos.sh",
      "verify_runtime_macos.sh",
    ];

    let suggestedMacCommand: string | undefined;
    if (macosPluginDir) {
      const wrapper = path.join(macosPluginDir, "pjarczak-bambu-linux-host-wrapper");
      const host = path.join(macosRuntimeDir, "pjarczak_bambu_linux_host");
      suggestedMacCommand =
        `PJARCZAK_BAMBU_PLUGIN_DIR=${shellQuote(macosRuntimeDir)} ` +
        `${shellQuote(wrapper)} ${shellQuote(host)}`;
    }

    return {
      configured: command.length > 0,
      command,
      platform: process.platform,
      running: Boolean(this.child && this.child.exitCode === null),
      pid: this.child?.pid,
      configDir,
      countryCode,
      agentReady: this.agentId !== undefined,
      lastStderr: this.lastStderr,
      recentLogs: this.recentLogs.slice(-10),
      runtime: {
        macosRuntimeDir,
        macosRuntimeDirExists: fileExists(macosRuntimeDir),
        macosPluginDir,
        macosPluginDirExists: macosPluginDir ? fileExists(macosPluginDir) : undefined,
        macosMissingRuntimeFiles: collectMissingFiles(macosRuntimeDir, runtimeRequiredFiles),
        macosMissingPluginFiles: collectMissingFiles(macosPluginDir, pluginRequiredFiles),
        suggestedMacCommand,
      },
      note: command
        ? undefined
        : "Set BAMBU_NETWORK_BRIDGE_COMMAND to the FULU OrcaSlicer-bambulab Linux host or macOS/WSL wrapper command.",
    };
  }

  async request(method: string, payload: JsonObject = {}, options: BambuNetworkBridgeOptions = {}): Promise<unknown> {
    if (!method.trim()) {
      throw new Error("BambuNetwork bridge method is required.");
    }

    await this.ensureStarted(options.bridgeCommand);

    const id = this.nextRequestId++;
    const requestPayload = Buffer.from(JSON.stringify({ method, payload }), "utf8");
    const frame = Buffer.alloc(FRAME_HEADER_SIZE + requestPayload.length);
    frame.writeUInt32LE(FRAME_MAGIC, 0);
    frame.writeUInt32LE(FRAME_TYPE_JSON_REQUEST, 4);
    frame.writeUInt32LE(id, 8);
    frame.writeUInt32LE(requestPayload.length, 12);
    requestPayload.copy(frame, FRAME_HEADER_SIZE);

    return await new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for FULU BambuNetwork bridge method ${method}.`));
      }, options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS);

      this.pending.set(id, { method, resolve, reject, timer });

      try {
        this.child!.stdin.write(frame, (error) => {
          if (error) {
            const pending = this.pending.get(id);
            if (pending) {
              clearTimeout(pending.timer);
              this.pending.delete(id);
              pending.reject(error);
            }
          }
        });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  async requestControl(
    method: string,
    payload: JsonObject = {},
    options: BambuNetworkBridgeOptions = {}
  ): Promise<unknown> {
    const activeCommand =
      this.child && this.child.exitCode === null ? this.commandLine : undefined;
    const explicitCommand = trimEnv(options.bridgeCommand);
    if (activeCommand) {
      if (explicitCommand && explicitCommand !== activeCommand) {
        throw new Error(
          "A BambuNetwork control call cannot switch bridge_command while a bridge process is active."
        );
      }
      return await this.request(method, payload, {
        ...options,
        bridgeCommand: activeCommand,
      });
    }
    return await this.request(method, payload, options);
  }

  async ensureAgent(options: BambuNetworkBridgeOptions = {}): Promise<{
    agent: number;
    handshake: unknown;
  }> {
    return await this.withAgentInitialization(
      async () => await this.ensureAgentUnlocked(options)
    );
  }

  private async ensureAgentUnlocked(options: BambuNetworkBridgeOptions = {}): Promise<{
    agent: number;
    handshake: unknown;
  }> {
    const command = this.resolveBridgeCommand(options.bridgeCommand);
    const configDir = this.resolveConfigDir(options.configDir);
    const countryCode = this.resolveCountryCode(options.countryCode);
    const userInfo = trimEnv(options.userInfo) || trimEnv(process.env.BAMBU_NETWORK_USER_INFO) || "";
    const certificateSources = this.resolveCertificateSources(options);
    const certificateStage = stageBambuNetworkCertificates(
      configDir,
      certificateSources.directories,
      certificateSources.strictDirectory
    );
    if (
      certificateSources.strictDirectory &&
      !certificateStage.certDir
    ) {
      throw new Error(
        "The explicitly configured BambuNetwork certificate bundle is incomplete. " +
        `Missing: ${certificateStage.missing.join(", ")}.`
      );
    }
    const certDir = certificateStage.certDir || "";
    const certFingerprint = certificateStage.fingerprint || "";
    const key = `${command}\n${configDir}\n${certDir}\n${certFingerprint}\n${countryCode}\n${userInfo}`;

    if (this.agentId !== undefined && this.agentKey === key) {
      return { agent: this.agentId, handshake: this.handshake };
    }

    if (this.agentId !== undefined) {
      const previousAgent = this.agentId;
      if (this.commandLine && this.commandLine !== command) {
        await this.stop();
      } else {
        try {
          const destroyed = await this.request(
            "net.destroy_agent",
            { agent: previousAgent },
            options
          );
          assertBridgeOk(destroyed, "net.destroy_agent");
          const destroyValue =
            typeof destroyed === "object" &&
            destroyed !== null &&
            typeof (destroyed as { value?: unknown }).value === "number"
              ? (destroyed as { value: number }).value
              : 0;
          if (destroyValue !== 0) {
            throw new Error(
              `FULU BambuNetwork bridge method net.destroy_agent returned non-zero result ${destroyValue}.`
            );
          }
        } catch {
          await this.stop();
        }
        if (this.agentId === previousAgent) {
          this.agentId = undefined;
          this.agentKey = undefined;
          this.agentCertDir = undefined;
        }
      }
    }

    fs.mkdirSync(configDir, { recursive: true });

    this.handshake = await this.request("bridge.handshake", {}, options);
    assertBridgeOk(this.handshake, "bridge.handshake");
    if (this.needsExpectedVersionRetry(this.handshake) && !trimEnv(process.env.PJARCZAK_EXPECTED_BAMBU_NETWORK_VERSION)) {
      this.inferredExpectedNetworkVersion = this.handshake.network_actual_abi_version;
      await this.stop();
      this.handshake = await this.request("bridge.handshake", {}, options);
      assertBridgeOk(this.handshake, "bridge.handshake");
    }

    const created = await this.request("net.create_agent", { log_dir: configDir, country_code: countryCode }, options);
    assertBridgeOk(created, "net.create_agent");
    const agent = bridgeValueAsNumber(created, "net.create_agent");

    const withAgent = async (method: string, payload: JsonObject = {}, hardFail = true): Promise<unknown> => {
      const response = await this.request(method, { ...payload, agent }, options);
      if (hardFail) assertBridgeOk(response, method);
      return response;
    };

    try {
      await withAgent("net.set_config_dir", { config_dir: configDir });
      await withAgent("net.init_log");
      if (certDir) {
        const certificateInitialized = await withAgent("net.set_cert_file", {
          folder: certDir,
          filename: "slicer_base64.cer",
        });
        const certificateResult = bridgeValueAsNumber(
          certificateInitialized,
          "net.set_cert_file"
        );
        if (certificateResult !== 0) {
          throw new Error(
            `FULU BambuNetwork bridge method net.set_cert_file returned non-zero result ${certificateResult}.`
          );
        }
      }
      await withAgent("net.set_country_code", { country_code: countryCode });
      await withAgent("net.set_queue_on_main_fn");
      await withAgent("net.set_on_printer_connected_fn", {}, false);
      await withAgent("net.set_on_server_connected_fn", {}, false);
      await withAgent("net.set_on_http_error_fn", {}, false);
      await withAgent("net.set_on_subscribe_failure_fn", {}, false);
      await withAgent("net.set_on_message_fn", {}, false);
      await withAgent("net.set_on_user_message_fn", {}, false);
      await withAgent("net.set_on_local_connect_fn", {}, false);
      await withAgent("net.set_on_local_message_fn", {}, false);
      await withAgent("net.set_server_callback", {}, false);
      await withAgent("net.start");
      await withAgent("net.connect_server", {}, false);

      if (userInfo) {
        await withAgent("net.change_user", { user_info: userInfo });
      }
    } catch (error) {
      try {
        const destroyed = await this.request(
          "net.destroy_agent",
          { agent },
          options
        );
        assertBridgeOk(destroyed, "net.destroy_agent");
        const destroyValue =
          typeof destroyed === "object" &&
          destroyed !== null &&
          typeof (destroyed as { value?: unknown }).value === "number"
            ? (destroyed as { value: number }).value
            : 0;
        if (destroyValue !== 0) {
          throw new Error(
            `FULU BambuNetwork bridge method net.destroy_agent returned non-zero result ${destroyValue}.`
          );
        }
      } catch {
        await this.stop();
      }
      throw error;
    }

    this.agentId = agent;
    this.agentKey = key;
    this.agentCertDir = certDir || undefined;
    return { agent, handshake: this.handshake };
  }

  async connectPrinter(
    connection: {
      devId: string;
      devIp: string;
      username: string;
      accessCode: string;
      useSsl: boolean;
    },
    options: BambuNetworkBridgeOptions = {}
  ): Promise<{
    connected: true;
    event: unknown;
    deviceCertificateRequested: boolean;
  }> {
    const { agent } = await this.ensureAgent(options);
    if (connection.useSsl && !this.agentCertDir) {
      const certificateSources = this.resolveCertificateSources(options);
      const missing = stageBambuNetworkCertificates(
        this.resolveConfigDir(options.configDir),
        certificateSources.directories,
        certificateSources.strictDirectory
      ).missing;
      throw new Error(
        `FULU BambuNetwork LAN connection requires its certificate bundle. Missing: ${missing.join(", ")}.`
      );
    }

    await this.discardQueuedEvents(options);
    const connected = await this.request(
      "net.connect_printer",
      {
        agent,
        dev_id: connection.devId,
        dev_ip: connection.devIp,
        username: connection.username,
        ["password"]: connection.accessCode,
        use_ssl: connection.useSsl,
      },
      options
    );
    assertBridgeOk(connected, "net.connect_printer");
    const result = bridgeValueAsNumber(connected, "net.connect_printer");
    if (result !== 0) {
      throw new Error(`FULU BambuNetwork bridge method net.connect_printer returned non-zero result ${result}.`);
    }

    const timeoutMs = Math.min(Math.max(options.timeoutMs ?? 15_000, 1_000), 60_000);
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      let events = this.preservedEvents.splice(0);
      if (events.length === 0) {
        const polled = await this.request("bridge.poll_events", { limit: 64 }, options);
        assertBridgeOk(polled, "bridge.poll_events");
        events =
          typeof polled === "object" &&
          polled !== null &&
          Array.isArray((polled as { events?: unknown }).events)
            ? (polled as { events: unknown[] }).events
            : [];
      }

      for (const event of events) {
        if (typeof event !== "object" || event === null) continue;
        const candidate = event as {
          name?: unknown;
          payload?: { status?: unknown; dev_id?: unknown };
        };
        if (
          candidate.name !== "on_local_connect" ||
          candidate.payload?.dev_id !== connection.devId
        ) {
          continue;
        }

        const status = Number(candidate.payload.status);
        if (status === 0) {
          const certificateRequest = await this.request(
            "net.install_device_cert",
            { agent, dev_id: connection.devId, lan_only: true },
            options
          );
          assertBridgeOk(certificateRequest, "net.install_device_cert");
          // install_device_cert is a void BambuNetwork ABI. The host can only
          // confirm that the request was dispatched, not that an asynchronous
          // certificate snapshot completed.
          return {
            connected: true,
            event,
            deviceCertificateRequested: true,
          };
        }
        if (status === 1 || status === 2) {
          const detail =
            typeof (candidate.payload as { msg?: unknown } | undefined)?.msg === "string"
              ? `: ${(candidate.payload as { msg: string }).msg}`
              : ".";
          throw new Error(`FULU BambuNetwork LAN connection failed with status ${status}${detail}`);
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 150));
    }

    await this.stop();
    throw new Error(
      `Timed out after ${timeoutMs} ms waiting for the FULU BambuNetwork LAN connection callback.`
    );
  }

  async discardQueuedEvents(options: BambuNetworkBridgeOptions = {}): Promise<number> {
    this.preservedEvents = [];
    this.preservedControlEvents = [];
    let discarded = 0;
    for (let batch = 0; batch < 32; batch += 1) {
      const polled = await this.request("bridge.poll_events", { limit: 64 }, options);
      assertBridgeOk(polled, "bridge.poll_events");
      const events =
        typeof polled === "object" &&
        polled !== null &&
        Array.isArray((polled as { events?: unknown }).events)
          ? (polled as { events: unknown[] }).events
          : [];
      discarded += events.length;
      if (events.length < 64) {
        return discarded;
      }
    }
    throw new Error("FULU BambuNetwork bridge event queue did not quiesce before print submission.");
  }

  async pollEventsForControl(
    payload: JsonObject = {},
    options: BambuNetworkBridgeOptions = {}
  ): Promise<unknown> {
    if (this.preservedControlEvents.length > 0) {
      const requestedLimit = Number(payload.limit);
      const limit =
        Number.isInteger(requestedLimit) && requestedLimit > 0
          ? requestedLimit
          : 64;
      return {
        ok: true,
        events: this.preservedControlEvents.splice(0, limit),
      };
    }
    const polled = await this.requestControl("bridge.poll_events", payload, options);
    assertBridgeOk(polled, "bridge.poll_events");
    const events =
      typeof polled === "object" &&
      polled !== null &&
      Array.isArray((polled as { events?: unknown }).events)
        ? (polled as { events: unknown[] }).events
        : [];
    this.preserveEvents(
      events.filter(
        (event) =>
          typeof event === "object" &&
          event !== null &&
          ["on_local_connect", "on_local_message"].includes(
            String((event as { name?: unknown }).name || "")
          )
      )
    );
    return polled;
  }

  async waitForLocalPrintAcknowledgement(
    devId: string,
    expectedSequenceId: string,
    options: BambuNetworkBridgeOptions = {}
  ): Promise<{ errCode: number; command: string; sequenceId: string }> {
    const expectedSequence = String(expectedSequenceId).trim();
    if (!expectedSequence) {
      throw new Error(
        "The BambuNetwork bridge did not expose the submitted project_file sequence_id. " +
        "Apply the bundled host and open-bambu-networking sequence-correlation patches."
      );
    }
    const timeoutMs = Math.max(options.confirmationTimeoutMs ?? 15_000, 1_000);
    const deadline = Date.now() + timeoutMs;
    const deferredEvents: unknown[] = [];

    while (Date.now() < deadline) {
      let events = this.preservedEvents.splice(0);
      if (events.length === 0) {
        const polled = await this.request("bridge.poll_events", { limit: 64 }, options);
        assertBridgeOk(polled, "bridge.poll_events");
        events =
          typeof polled === "object" &&
          polled !== null &&
          Array.isArray((polled as { events?: unknown }).events)
            ? (polled as { events: unknown[] }).events
            : [];
      }

      for (let index = 0; index < events.length; index += 1) {
        const event = events[index];
        if (typeof event !== "object" || event === null) {
          this.preserveControlEvents([event]);
          continue;
        }
        const candidate = event as {
          name?: unknown;
          payload?: { dev_id?: unknown; msg?: unknown };
        };
        if (
          candidate.name !== "on_local_message" ||
          candidate.payload?.dev_id !== devId ||
          typeof candidate.payload.msg !== "string"
        ) {
          this.preserveControlEvents([event]);
          continue;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(candidate.payload.msg);
        } catch {
          this.preserveControlEvents([event]);
          continue;
        }
        const print =
          typeof parsed === "object" &&
          parsed !== null &&
          typeof (parsed as { print?: unknown }).print === "object" &&
          (parsed as { print?: unknown }).print !== null
            ? (parsed as { print: Record<string, unknown> }).print
            : undefined;
        if (print?.command !== "project_file") {
          deferredEvents.push(event);
          this.preserveControlEvents([event]);
          continue;
        }

        const sequenceId = String(print.sequence_id ?? "").trim();
        const hasSequenceId =
          print.sequence_id !== undefined &&
          print.sequence_id !== null &&
          print.sequence_id !== "" &&
          sequenceId.length > 0;
        if (!hasSequenceId || sequenceId !== expectedSequence) {
          this.preserveControlEvents([event]);
          continue;
        }

        const errCode = Number(print.err_code ?? print.error_code ?? print.errCode ?? 0);
        if (Number.isFinite(errCode) && errCode !== 0) {
          this.preserveEvents([
            ...deferredEvents,
            ...events.slice(index + 1),
          ]);
          this.preserveControlEvents([
            ...events.slice(index + 1),
          ]);
          if (errCode === 84033543) {
            throw new Error(
              "The printer rejected the project_file command with error 84033543 (MQTT command verification failed). Enable Developer Mode on the printer for open BambuNetwork LAN printing, or use an authenticated stock-plugin print path."
            );
          }
          throw new Error(`The printer rejected the project_file command with error ${errCode}.`);
        }

        const result = String(print.result || "").toLowerCase();
        if (result === "fail" || result === "failed") {
          this.preserveEvents([
            ...deferredEvents,
            ...events.slice(index + 1),
          ]);
          this.preserveControlEvents([
            ...events.slice(index + 1),
          ]);
          const reason = print.reason ? `: ${String(print.reason)}` : ".";
          throw new Error(`The printer rejected the project_file command${reason}`);
        }

        if (result !== "success" && result !== "ok") {
          continue;
        }

        this.preserveEvents([
          ...deferredEvents,
          ...events.slice(index + 1),
        ]);
        this.preserveControlEvents([
          ...events.slice(index + 1),
        ]);
        return { errCode: 0, command: "project_file", sequenceId };
      }

      await new Promise((resolve) => setTimeout(resolve, 150));
    }

    this.preserveEvents(deferredEvents);
    await this.stop();
    throw new Error(
      `Timed out after ${timeoutMs} ms waiting for the printer to acknowledge the project_file command.`
    );
  }

  async waitForPrinterJobStart(
    devId: string,
    expectedNames: string[],
    options: BambuNetworkBridgeOptions = {}
  ): Promise<{ state: string; filename: string }> {
    const normalize = (value: unknown): string =>
      path.basename(String(value || ""))
        .toLowerCase()
        .replace(/(?:\.gcode)?\.3mf$/i, "")
        .replace(/\.gcode$/i, "")
        .replace(/[^a-z0-9]+/g, "_")
        .replace(/^_+|_+$/g, "");
    const expected = expectedNames.map(normalize).filter(Boolean);
    const activeStates = new Set(["PREPARE", "RUNNING"]);
    const timeoutMs = Math.max(options.confirmationTimeoutMs ?? 15_000, 1_000);
    const deadline = Date.now() + timeoutMs;
    let observedState = "UNKNOWN";
    let observedFilename = "None";

    while (Date.now() < deadline) {
      let events = this.preservedEvents.splice(0);
      if (events.length === 0) {
        const polled = await this.request("bridge.poll_events", { limit: 64 }, options);
        assertBridgeOk(polled, "bridge.poll_events");
        events =
          typeof polled === "object" &&
          polled !== null &&
          Array.isArray((polled as { events?: unknown }).events)
            ? (polled as { events: unknown[] }).events
            : [];
      }

      for (let index = 0; index < events.length; index += 1) {
        const event = events[index];
        if (typeof event !== "object" || event === null) {
          this.preserveControlEvents([event]);
          continue;
        }
        const candidate = event as {
          name?: unknown;
          payload?: { dev_id?: unknown; msg?: unknown };
        };
        if (
          candidate.name !== "on_local_message" ||
          candidate.payload?.dev_id !== devId ||
          typeof candidate.payload.msg !== "string"
        ) {
          this.preserveControlEvents([event]);
          continue;
        }

        let parsed: unknown;
        try {
          parsed = JSON.parse(candidate.payload.msg);
        } catch {
          this.preserveControlEvents([event]);
          continue;
        }
        const print =
          typeof parsed === "object" &&
          parsed !== null &&
          typeof (parsed as { print?: unknown }).print === "object" &&
          (parsed as { print?: unknown }).print !== null
            ? (parsed as { print: Record<string, unknown> }).print
            : undefined;
        if (print?.command !== "push_status") {
          this.preserveControlEvents([event]);
          continue;
        }
        this.preserveControlEvents([event]);

        const reportedFilename = print.subtask_name ?? print.gcode_file;
        if (
          reportedFilename !== undefined &&
          reportedFilename !== null &&
          String(reportedFilename).trim()
        ) {
          const nextFilename = String(reportedFilename);
          if (normalize(nextFilename) !== normalize(observedFilename)) {
            observedState = "UNKNOWN";
          }
          observedFilename = nextFilename;
        }
        if (print.gcode_state !== undefined && print.gcode_state !== null) {
          observedState = String(print.gcode_state).trim().toUpperCase();
        }
        if (activeStates.has(observedState)) {
          const actual = normalize(observedFilename);
          if (!actual || actual === "none") {
            continue;
          }
          const matches = expected.some(
            (expectedName) =>
              actual === expectedName ||
              actual.startsWith(`${expectedName}_plate_`)
          );
          if (!matches) {
            continue;
          }
          this.preserveControlEvents([
            ...events.slice(index + 1),
          ]);
          return { state: observedState, filename: observedFilename };
        }
      }

      await new Promise((resolve) => setTimeout(resolve, 250));
    }

    throw new Error(
      `Timed out after ${timeoutMs} ms waiting for the exact BambuNetwork job to enter PREPARE or RUNNING.`
    );
  }

  async callWithAgent(
    method: string,
    payload: JsonObject = {},
    options: BambuNetworkBridgeOptions = {}
  ): Promise<unknown> {
    const { agent } = await this.ensureAgent(options);
    return await this.request(method, { ...payload, agent }, options);
  }

  async stop(): Promise<void> {
    const child = this.child;
    this.child = undefined;
    this.commandLine = undefined;
    this.agentId = undefined;
    this.agentKey = undefined;
    this.agentCertDir = undefined;
    this.handshake = undefined;
    this.stdoutBuffer = Buffer.alloc(0);
    this.preservedEvents = [];
    this.preservedControlEvents = [];

    for (const [id, pending] of this.pending.entries()) {
      clearTimeout(pending.timer);
      pending.reject(new Error(`FULU BambuNetwork bridge stopped before ${pending.method} completed.`));
      this.pending.delete(id);
    }

    if (child && child.exitCode === null) {
      await new Promise<void>((resolve) => {
        const forceTimer = setTimeout(() => {
          if (child.exitCode === null) {
            child.kill("SIGKILL");
          }
        }, 2000);
        child.once("close", () => {
          clearTimeout(forceTimer);
          resolve();
        });
        child.kill("SIGTERM");
      });
    }
  }

  private async ensureStarted(commandOverride?: string): Promise<void> {
    const command = this.resolveBridgeCommand(commandOverride);
    if (!command) {
      throw new Error(
        "BAMBU_NETWORK_BRIDGE_COMMAND is required for FULU BambuNetwork support. " +
        "Point it at pjarczak_bambu_linux_host or the OrcaSlicer-bambulab macOS/WSL wrapper."
      );
    }

    if (this.child && this.child.exitCode === null && this.commandLine === command) {
      return;
    }

    if (this.child && this.commandLine !== command) {
      await this.stop();
    }

    const shell = process.platform === "win32" ? process.env.ComSpec || "cmd.exe" : "/bin/sh";
    const shellArgs = process.platform === "win32"
      ? ["/d", "/s", "/c", command]
      : ["-lc", command];

    this.child = spawn(shell, shellArgs, {
      env: {
        ...process.env,
        PJARCZAK_BAMBU_COUNTRY_CODE: this.resolveCountryCode(),
        PJARCZAK_EXPECTED_BAMBU_NETWORK_VERSION:
          this.inferredExpectedNetworkVersion ||
          process.env.PJARCZAK_EXPECTED_BAMBU_NETWORK_VERSION ||
          "",
      },
      stdio: ["pipe", "pipe", "pipe"],
    });
    this.commandLine = command;

    const spawnedChild = this.child;
    spawnedChild.stdout.on("data", (chunk: Buffer) => this.handleStdout(chunk));
    spawnedChild.stderr.on("data", (chunk: Buffer) => this.rememberStderr(chunk.toString("utf8")));
    spawnedChild.on("error", (error) => {
      if (this.child === spawnedChild) {
        this.rejectAllPending(error);
      }
    });
    spawnedChild.on("close", (code, signal) => {
      if (this.child !== spawnedChild) {
        return;
      }
      this.rejectAllPending(
        new Error(`FULU BambuNetwork bridge exited (code=${code ?? "null"}, signal=${signal ?? "null"}). ${this.lastStderr}`.trim())
      );
      this.child = undefined;
      this.commandLine = undefined;
      this.agentId = undefined;
      this.agentKey = undefined;
      this.agentCertDir = undefined;
      this.handshake = undefined;
      this.preservedEvents = [];
      this.preservedControlEvents = [];
    });
  }

  private handleStdout(chunk: Buffer): void {
    this.stdoutBuffer = Buffer.concat([this.stdoutBuffer, chunk]);

    while (this.stdoutBuffer.length >= FRAME_HEADER_SIZE) {
      const magic = this.stdoutBuffer.readUInt32LE(0);
      if (magic !== FRAME_MAGIC) {
        const preview = this.stdoutBuffer.subarray(0, Math.min(this.stdoutBuffer.length, 120)).toString("utf8");
        this.rejectAllPending(new Error(`Invalid FULU BambuNetwork bridge frame magic. Output began with: ${preview}`));
        this.stdoutBuffer = Buffer.alloc(0);
        return;
      }

      const type = this.stdoutBuffer.readUInt32LE(4);
      const id = this.stdoutBuffer.readUInt32LE(8);
      const size = this.stdoutBuffer.readUInt32LE(12);
      if (this.stdoutBuffer.length < FRAME_HEADER_SIZE + size) {
        return;
      }

      const payload = this.stdoutBuffer.subarray(FRAME_HEADER_SIZE, FRAME_HEADER_SIZE + size);
      this.stdoutBuffer = this.stdoutBuffer.subarray(FRAME_HEADER_SIZE + size);

      if (type === FRAME_TYPE_JSON_RESPONSE) {
        this.resolvePendingJson(id, payload);
      } else if (type === FRAME_TYPE_LOG) {
        this.rememberLog(payload.toString("utf8"));
      } else if (type === FRAME_TYPE_BINARY_DATA) {
        this.rememberLog(`received ${payload.length} bytes of bridge binary data for request ${id}`);
      } else {
        this.rememberLog(`ignored bridge frame type ${type} for request ${id}`);
      }
    }
  }

  private resolvePendingJson(id: number, payload: Buffer): void {
    const pending = this.pending.get(id);
    if (!pending) {
      this.rememberLog(`received response for unknown bridge request ${id}`);
      return;
    }

    clearTimeout(pending.timer);
    this.pending.delete(id);

    try {
      pending.resolve(readFrameJson(payload));
    } catch (error) {
      pending.reject(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private rememberLog(message: string): void {
    const trimmed = message.trim();
    if (!trimmed) return;
    this.recentLogs.push(redactBambuNetworkDiagnostic(trimmed));
    if (this.recentLogs.length > 25) {
      this.recentLogs = this.recentLogs.slice(-25);
    }
  }

  private rememberStderr(message: string): void {
    const combined = `${this.lastStderr}${message}`;
    const sanitized = redactBambuNetworkDiagnostic(combined);
    this.lastStderr = sanitized.length > 4000 ? sanitized.slice(-4000) : sanitized;
  }

  private rejectAllPending(error: Error): void {
    for (const [id, pending] of this.pending.entries()) {
      clearTimeout(pending.timer);
      pending.reject(error);
      this.pending.delete(id);
    }
  }

  private needsExpectedVersionRetry(handshake: unknown): handshake is {
    network_actual_abi_version: string;
    network_loaded?: boolean;
    network_status?: string;
  } {
    if (typeof handshake !== "object" || handshake === null) {
      return false;
    }

    const value = handshake as {
      network_actual_abi_version?: unknown;
      network_loaded?: unknown;
      network_status?: unknown;
    };

    return (
      value.network_loaded === false &&
      typeof value.network_actual_abi_version === "string" &&
      value.network_actual_abi_version.length > 0 &&
      typeof value.network_status === "string" &&
      value.network_status.toLowerCase().includes("expected abi version")
    );
  }
}
