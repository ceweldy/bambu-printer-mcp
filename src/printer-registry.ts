import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export const SUPPORTED_BAMBU_MODELS = [
  "p1s",
  "p1p",
  "p2s",
  "x1c",
  "x1e",
  "a1",
  "a1mini",
  "h2d",
  "h2s",
  "h2c",
] as const;

export type SupportedBambuModel = (typeof SUPPORTED_BAMBU_MODELS)[number];

export interface PrinterProfileInput {
  id: string;
  name?: string;
  host: string;
  model: string;
  serial?: string;
  serialEnv?: string;
  accessToken?: string;
  accessTokenEnv?: string;
  devId?: string;
  devIdEnv?: string;
  bedType?: string;
  nozzleDiameter?: string;
  default?: boolean;
}

interface StoredPrinterProfile
  extends Omit<PrinterProfileInput, "serial" | "accessToken" | "devId" | "default"> {}

interface ManagedPrinterProfile extends PrinterProfileInput {
  source: "file" | "json-env" | "legacy-env" | "runtime";
}

export interface ResolvedPrinterProfile {
  id: string;
  name: string;
  host: string;
  serial: string;
  accessToken: string;
  model: SupportedBambuModel;
  devId: string;
  bedType?: string;
  nozzleDiameter?: string;
  source: ManagedPrinterProfile["source"];
}

export interface PrinterProfileSummary {
  id: string;
  name: string;
  model: SupportedBambuModel;
  is_default: boolean;
  ready: boolean;
  source: ManagedPrinterProfile["source"];
  host_configured: true;
  serial_source: "inline" | "environment" | "missing";
  credential_source: "runtime" | "environment" | "missing";
  missing_environment_variables: string[];
  bed_type: string | null;
  nozzle_diameter: string | null;
}

type RegistryFile = {
  version: 1;
  defaultPrinter?: string;
  printers: StoredPrinterProfile[];
};

type RegistryOptions = {
  env?: NodeJS.ProcessEnv;
  configPath?: string;
  homeDir?: string;
};

type ResolveOverrides = {
  host?: string;
  serial?: string;
  accessToken?: string;
  model?: string;
  devId?: string;
  bedType?: string;
  nozzleDiameter?: string;
};

const PROFILE_ID_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const HOST_PATTERN = /^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$/;
const ENV_NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;
const BED_TYPES = new Set([
  "textured_plate",
  "cool_plate",
  "engineering_plate",
  "hot_plate",
  "supertack_plate",
]);

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${label} is required.`);
  }
  return value.trim();
}

function optionalString(value: unknown): string | undefined {
  if (typeof value !== "string") return undefined;
  const normalized = value.trim();
  return normalized.length > 0 ? normalized : undefined;
}

function validateEnvName(value: string | undefined, label: string): string | undefined {
  if (!value) return undefined;
  if (!ENV_NAME_PATTERN.test(value)) {
    throw new Error(`${label} must be an uppercase environment-variable name.`);
  }
  return value;
}

function validateModel(value: unknown): SupportedBambuModel {
  const model = requiredString(value, "model").toLowerCase();
  if (!(SUPPORTED_BAMBU_MODELS as readonly string[]).includes(model)) {
    throw new Error(
      `Unsupported printer model "${model}". Supported models: ${SUPPORTED_BAMBU_MODELS.join(", ")}.`
    );
  }
  return model as SupportedBambuModel;
}

function validateProfile(
  raw: PrinterProfileInput,
  source: ManagedPrinterProfile["source"],
  allowInlineToken: boolean
): ManagedPrinterProfile {
  const id = requiredString(raw.id, "printer id").toLowerCase();
  if (!PROFILE_ID_PATTERN.test(id)) {
    throw new Error(
      `Invalid printer id "${id}". Use 1-64 lowercase letters, numbers, dots, underscores, or hyphens.`
    );
  }
  if (id === "all") {
    throw new Error('Printer id "all" is reserved for fleet operations.');
  }

  const host = requiredString(raw.host, `host for printer "${id}"`);
  if (!HOST_PATTERN.test(host) || host.includes("..")) {
    throw new Error(`Invalid host for printer "${id}". Use a hostname or IP address without a URL scheme or port.`);
  }

  const accessToken = optionalString(raw.accessToken);
  const serial = optionalString(raw.serial);
  if (serial && !allowInlineToken) {
    throw new Error(
      `Printer "${id}" contains a plaintext serial in the config file. ` +
      "Move it to an environment variable and set serialEnv instead."
    );
  }
  if (accessToken && !allowInlineToken) {
    throw new Error(
      `Printer "${id}" contains a plaintext accessToken in the config file. ` +
      "Move it to an environment variable and set accessTokenEnv instead."
    );
  }
  const devId = optionalString(raw.devId);
  if (devId && !allowInlineToken) {
    throw new Error(
      `Printer "${id}" contains a plaintext devId in the config file. ` +
      "Move it to an environment variable and set devIdEnv instead."
    );
  }

  const serialEnv = validateEnvName(optionalString(raw.serialEnv), `serialEnv for printer "${id}"`);
  const accessTokenEnv = validateEnvName(
    optionalString(raw.accessTokenEnv),
    `accessTokenEnv for printer "${id}"`
  );
  const devIdEnv = validateEnvName(optionalString(raw.devIdEnv), `devIdEnv for printer "${id}"`);
  const bedType = optionalString(raw.bedType)?.toLowerCase();
  if (bedType && !BED_TYPES.has(bedType)) {
    throw new Error(`Invalid bedType for printer "${id}".`);
  }

  const nozzleDiameter = optionalString(raw.nozzleDiameter);
  if (nozzleDiameter && !/^(0\.2|0\.4|0\.6|0\.8)$/.test(nozzleDiameter)) {
    throw new Error(`Invalid nozzleDiameter for printer "${id}". Use 0.2, 0.4, 0.6, or 0.8.`);
  }

  return {
    id,
    name: optionalString(raw.name) || id,
    host,
    model: validateModel(raw.model),
    serial,
    serialEnv,
    accessToken,
    accessTokenEnv,
    devId,
    devIdEnv,
    bedType,
    nozzleDiameter,
    default: raw.default === true,
    source,
  };
}

function parseRegistryPayload(raw: string, label: string): { profiles: PrinterProfileInput[]; defaultPrinter?: string } {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`${label} is not valid JSON: ${(error as Error).message}`);
  }

  if (Array.isArray(parsed)) {
    return { profiles: parsed as PrinterProfileInput[] };
  }

  if (!parsed || typeof parsed !== "object") {
    throw new Error(`${label} must be a JSON array or an object with a printers array.`);
  }

  const object = parsed as Record<string, unknown>;
  if (!Array.isArray(object.printers)) {
    throw new Error(`${label} must contain a printers array.`);
  }
  if (object.version !== undefined && object.version !== 1) {
    throw new Error(`${label} uses unsupported version ${String(object.version)}. Expected version 1.`);
  }

  return {
    profiles: object.printers as PrinterProfileInput[],
    defaultPrinter: optionalString(object.defaultPrinter),
  };
}

export class PrinterRegistry {
  private readonly env: NodeJS.ProcessEnv;
  private readonly configPath: string;
  private readonly ownsConfigDirectory: boolean;
  private readonly profiles = new Map<string, ManagedPrinterProfile>();
  private readonly commandTails = new Map<string, Promise<unknown>>();
  private defaultPrinterId?: string;

  constructor(options: RegistryOptions = {}) {
    this.env = options.env ?? process.env;
    const homeDir = options.homeDir ?? os.homedir();
    const configuredPath = options.configPath ?? this.env.BAMBU_PRINTERS_FILE;
    this.configPath = configuredPath ?? path.join(
      homeDir,
      ".config",
      "bambu-printer-mcp",
      "printers.json"
    );
    this.ownsConfigDirectory = configuredPath === undefined;
    this.load();
  }

  get size(): number {
    return this.profiles.size;
  }

  get path(): string {
    return this.configPath;
  }

  has(id: string): boolean {
    return this.profiles.has(id.trim().toLowerCase());
  }

  private assertNoDuplicatePhysicalPrinter(candidate: ManagedPrinterProfile): void {
    const candidateSerial = candidate.serial || optionalString(
      candidate.serialEnv ? this.env[candidate.serialEnv] : undefined
    );
    if (!candidateSerial) return;
    for (const existing of this.profiles.values()) {
      if (existing.id === candidate.id) continue;
      const existingSerial = existing.serial || optionalString(
        existing.serialEnv ? this.env[existing.serialEnv] : undefined
      );
      if (existingSerial && existingSerial === candidateSerial) {
        throw new Error(
          `Printer profiles "${candidate.id}" and "${existing.id}" resolve to the same physical printer.`
        );
      }
    }
  }

  targetId(id?: string): string {
    const normalizedId = optionalString(id)?.toLowerCase();
    if (normalizedId === "all") {
      throw new Error('The "all" target is only supported by fleet-specific tools.');
    }
    if (normalizedId) {
      if (!this.profiles.has(normalizedId)) {
        throw new Error(
          `Unknown printer "${id}". Configured printers: ${this.list().map((entry) => entry.id).join(", ") || "none"}.`
        );
      }
      return normalizedId;
    }
    if (this.defaultPrinterId) return this.defaultPrinterId;
    if (this.profiles.size === 1) return this.profiles.keys().next().value as string;
    if (this.profiles.size > 1) {
      throw new Error(
        `Multiple printers are configured. Pass printer with one of: ${this.list().map((entry) => entry.id).join(", ")}.`
      );
    }
    return "adhoc";
  }

  implicitReadyTargetId(): string | undefined {
    const id = this.defaultPrinterId ?? (
      this.profiles.size === 1 ? this.profiles.keys().next().value as string : undefined
    );
    if (!id) return undefined;
    const profile = this.profiles.get(id);
    return profile && this.summarize(profile).ready ? id : undefined;
  }

  private load(): void {
    this.profiles.clear();
    this.defaultPrinterId = undefined;

    if (this.env.BAMBU_PRINTERS_JSON?.trim()) {
      const payload = parseRegistryPayload(this.env.BAMBU_PRINTERS_JSON, "BAMBU_PRINTERS_JSON");
      this.installProfiles(payload.profiles, "json-env", true, payload.defaultPrinter);
      return;
    }

    if (fs.existsSync(this.configPath)) {
      const payload = parseRegistryPayload(fs.readFileSync(this.configPath, "utf8"), this.configPath);
      this.installProfiles(payload.profiles, "file", false, payload.defaultPrinter);
      return;
    }

    const serial = optionalString(this.env.BAMBU_PRINTER_SERIAL || this.env.BAMBU_SERIAL);
    const accessToken = optionalString(
      this.env.BAMBU_PRINTER_ACCESS_TOKEN || this.env.BAMBU_TOKEN
    );
    const model = optionalString(this.env.BAMBU_PRINTER_MODEL || this.env.BAMBU_MODEL);
    const explicitHost = optionalString(this.env.BAMBU_PRINTER_HOST || this.env.PRINTER_HOST);
    if (serial || accessToken || model || explicitHost) {
      if (!serial || !accessToken || !model) {
        return;
      }
      const host = explicitHost || "localhost";
      this.installProfiles(
        [
          {
            id: optionalString(this.env.BAMBU_PRINTER_ID) || "default",
            name: optionalString(this.env.BAMBU_PRINTER_NAME) || "Default printer",
            host,
            serial,
            accessToken,
            model,
            devId: optionalString(this.env.BAMBU_DEV_ID),
            bedType: optionalString(this.env.BED_TYPE),
            nozzleDiameter: optionalString(this.env.NOZZLE_DIAMETER),
            default: true,
          },
        ],
        "legacy-env",
        true
      );
    }
  }

  private installProfiles(
    rawProfiles: PrinterProfileInput[],
    source: ManagedPrinterProfile["source"],
    allowInlineToken: boolean,
    defaultPrinter?: string
  ): void {
    for (const rawProfile of rawProfiles) {
      const profile = validateProfile(rawProfile, source, allowInlineToken);
      if (this.profiles.has(profile.id)) {
        throw new Error(`Duplicate printer id "${profile.id}".`);
      }
      this.assertNoDuplicatePhysicalPrinter(profile);
      this.profiles.set(profile.id, profile);
      if (profile.default) {
        if (this.defaultPrinterId && this.defaultPrinterId !== profile.id) {
          throw new Error("Only one printer may be marked as default.");
        }
        this.defaultPrinterId = profile.id;
      }
    }

    if (defaultPrinter) {
      const normalized = defaultPrinter.trim().toLowerCase();
      if (!this.profiles.has(normalized)) {
        throw new Error(`Default printer "${defaultPrinter}" does not exist.`);
      }
      if (this.defaultPrinterId && this.defaultPrinterId !== normalized) {
        throw new Error("The config declares conflicting default printers.");
      }
      this.defaultPrinterId = normalized;
    }
  }

  list(): PrinterProfileSummary[] {
    return [...this.profiles.values()]
      .map((profile) => this.summarize(profile))
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  private summarize(profile: ManagedPrinterProfile): PrinterProfileSummary {
    const missing: string[] = [];
    if (profile.serialEnv && !optionalString(this.env[profile.serialEnv])) missing.push(profile.serialEnv);
    if (profile.accessTokenEnv && !optionalString(this.env[profile.accessTokenEnv])) {
      missing.push(profile.accessTokenEnv);
    }
    if (profile.devIdEnv && !optionalString(this.env[profile.devIdEnv])) missing.push(profile.devIdEnv);

    const serialReady = Boolean(profile.serial || (profile.serialEnv && !missing.includes(profile.serialEnv)));
    const tokenReady = Boolean(
      profile.accessToken || (profile.accessTokenEnv && !missing.includes(profile.accessTokenEnv))
    );

    return {
      id: profile.id,
      name: profile.name || profile.id,
      model: profile.model as SupportedBambuModel,
      is_default: profile.id === this.defaultPrinterId,
      ready: serialReady && tokenReady,
      source: profile.source,
      host_configured: true,
      serial_source: profile.serial ? "inline" : profile.serialEnv ? "environment" : "missing",
      credential_source: profile.accessToken
        ? "runtime"
        : profile.accessTokenEnv
          ? "environment"
          : "missing",
      missing_environment_variables: missing,
      bed_type: profile.bedType || null,
      nozzle_diameter: profile.nozzleDiameter || null,
    };
  }

  resolve(id?: string, overrides: ResolveOverrides = {}): ResolvedPrinterProfile {
    const normalizedId = optionalString(id)?.toLowerCase();
    if (normalizedId === "all") {
      throw new Error('The "all" target is only supported by fleet-specific tools.');
    }

    let profile: ManagedPrinterProfile | undefined;
    if (normalizedId) {
      profile = this.profiles.get(normalizedId);
      if (!profile) {
        throw new Error(
          `Unknown printer "${id}". Configured printers: ${this.list().map((entry) => entry.id).join(", ") || "none"}.`
        );
      }
    } else if (this.defaultPrinterId) {
      profile = this.profiles.get(this.defaultPrinterId);
    } else if (this.profiles.size === 1) {
      profile = this.profiles.values().next().value;
    } else if (this.profiles.size > 1) {
      throw new Error(
        `Multiple printers are configured. Pass printer with one of: ${this.list().map((entry) => entry.id).join(", ")}.`
      );
    }

    if (!profile) {
      if (!overrides.host || !overrides.serial || !overrides.accessToken || !overrides.model) {
        throw new Error(
          "No ready printer is configured. Configure BAMBU_PRINTERS_JSON/BAMBU_PRINTERS_FILE, " +
          "use the add_printer tool, or provide host, bambu_serial, bambu_token, and bambu_model."
        );
      }
      profile = validateProfile(
        {
          id: "adhoc",
          name: "Ad hoc printer",
          host: overrides.host,
          serial: overrides.serial,
          accessToken: overrides.accessToken,
          model: overrides.model,
          devId: overrides.devId,
          bedType: overrides.bedType,
          nozzleDiameter: overrides.nozzleDiameter,
        },
        "runtime",
        true
      );
    }

    const serial = optionalString(overrides.serial) || profile.serial || optionalString(
      profile.serialEnv ? this.env[profile.serialEnv] : undefined
    );
    const accessToken = optionalString(overrides.accessToken) || profile.accessToken || optionalString(
      profile.accessTokenEnv ? this.env[profile.accessTokenEnv] : undefined
    );
    const host = optionalString(overrides.host) || profile.host;
    const model = validateModel(optionalString(overrides.model) || profile.model);
    const devId =
      optionalString(overrides.devId) ||
      profile.devId ||
      optionalString(profile.devIdEnv ? this.env[profile.devIdEnv] : undefined) ||
      serial;

    const missing: string[] = [];
    if (!serial) missing.push(profile.serialEnv || "serial");
    if (!accessToken) missing.push(profile.accessTokenEnv || "access token");
    if (missing.length > 0) {
      throw new Error(`Printer "${profile.id}" is not ready. Missing: ${missing.join(", ")}.`);
    }

    if (profile.id !== "adhoc") {
      for (const other of this.profiles.values()) {
        if (other.id === profile.id) continue;
        const otherSerial = other.serial || optionalString(
          other.serialEnv ? this.env[other.serialEnv] : undefined
        );
        if (otherSerial && otherSerial === serial) {
          throw new Error(
            `Printer profiles "${profile.id}" and "${other.id}" resolve to the same physical printer.`
          );
        }
      }
    }

    return {
      id: profile.id,
      name: profile.name || profile.id,
      host,
      serial: serial as string,
      accessToken: accessToken as string,
      model,
      devId: devId as string,
      bedType: optionalString(overrides.bedType) || profile.bedType,
      nozzleDiameter: optionalString(overrides.nozzleDiameter) || profile.nozzleDiameter,
      source: profile.source,
    };
  }

  resolveAll(): { resolved: ResolvedPrinterProfile[]; unavailable: PrinterProfileSummary[] } {
    const resolved: ResolvedPrinterProfile[] = [];
    const unavailable: PrinterProfileSummary[] = [];
    for (const summary of this.list()) {
      try {
        resolved.push(this.resolve(summary.id));
      } catch {
        unavailable.push(summary);
      }
    }
    return { resolved, unavailable };
  }

  add(
    rawProfile: PrinterProfileInput,
    options: { persist?: boolean; replace?: boolean } = {}
  ): PrinterProfileSummary {
    const profile = validateProfile(rawProfile, "runtime", true);
    const previousProfile = this.profiles.get(profile.id);
    const previousDefault = this.defaultPrinterId;
    if (previousProfile && options.replace !== true) {
      throw new Error(`Printer "${profile.id}" already exists. Pass replace:true to update it.`);
    }
    if (options.persist && (!profile.serialEnv || !profile.accessTokenEnv)) {
      throw new Error(
        "Refusing to persist runtime-only printer identifiers or credentials. " +
        "Set serial_env and access_token_env, then provide both values through those environment variables."
      );
    }
    if (options.persist && profile.devId && !profile.devIdEnv) {
      throw new Error(
        "Refusing to persist an inline BambuNetwork device identifier. " +
        "Set dev_id_env and provide the value through that environment variable."
      );
    }

    this.assertNoDuplicatePhysicalPrinter(profile);

    this.profiles.set(profile.id, profile);
    if (profile.default || this.profiles.size === 1) this.defaultPrinterId = profile.id;
    try {
      if (options.persist) this.persist();
    } catch (error) {
      if (previousProfile) this.profiles.set(profile.id, previousProfile);
      else this.profiles.delete(profile.id);
      this.defaultPrinterId = previousDefault;
      throw error;
    }
    return this.summarize(profile);
  }

  remove(id: string, options: { persist?: boolean } = {}): PrinterProfileSummary {
    const normalized = requiredString(id, "printer id").toLowerCase();
    const profile = this.profiles.get(normalized);
    if (!profile) throw new Error(`Unknown printer "${id}".`);
    const summary = this.summarize(profile);
    const previousDefault = this.defaultPrinterId;
    this.profiles.delete(normalized);
    if (this.defaultPrinterId === normalized) {
      this.defaultPrinterId = this.profiles.size === 1 ? this.profiles.keys().next().value : undefined;
    }
    try {
      if (options.persist) this.persist();
    } catch (error) {
      this.profiles.set(normalized, profile);
      this.defaultPrinterId = previousDefault;
      throw error;
    }
    return summary;
  }

  setDefault(id: string, options: { persist?: boolean } = {}): PrinterProfileSummary {
    const normalized = requiredString(id, "printer id").toLowerCase();
    const profile = this.profiles.get(normalized);
    if (!profile) throw new Error(`Unknown printer "${id}".`);
    const previousDefault = this.defaultPrinterId;
    this.defaultPrinterId = normalized;
    try {
      if (options.persist) this.persist();
    } catch (error) {
      this.defaultPrinterId = previousDefault;
      throw error;
    }
    return this.summarize(profile);
  }

  async runExclusive<T>(printerId: string, operation: () => Promise<T>): Promise<T> {
    const prior = this.commandTails.get(printerId) ?? Promise.resolve();
    const current = prior.catch(() => undefined).then(operation);
    this.commandTails.set(printerId, current);
    try {
      return await current;
    } finally {
      if (this.commandTails.get(printerId) === current) this.commandTails.delete(printerId);
    }
  }

  private persist(): void {
    const runtimeOnlyProfiles = [...this.profiles.values()]
      .filter((profile) => !profile.serialEnv || !profile.accessTokenEnv)
      .map((profile) => profile.id);
    if (runtimeOnlyProfiles.length > 0) {
      throw new Error(
        `Cannot persist the registry while these profiles lack serial_env or access_token_env references: ${runtimeOnlyProfiles.join(", ")}.`
      );
    }
    const inlineDeviceIds = [...this.profiles.values()]
      .filter((profile) => profile.devId && !profile.devIdEnv)
      .map((profile) => profile.id);
    if (inlineDeviceIds.length > 0) {
      throw new Error(
        `Cannot persist the registry while these profiles lack dev_id_env references: ${inlineDeviceIds.join(", ")}.`
      );
    }

    const directory = path.dirname(this.configPath);
    const directoryExisted = fs.existsSync(directory);
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    if (!directoryExisted || this.ownsConfigDirectory) fs.chmodSync(directory, 0o700);

    const printers: StoredPrinterProfile[] = [...this.profiles.values()].map((profile) => ({
      id: profile.id,
      name: profile.name,
      host: profile.host,
      model: profile.model,
      serialEnv: profile.serialEnv,
      accessTokenEnv: profile.accessTokenEnv,
      devIdEnv: profile.devIdEnv,
      bedType: profile.bedType,
      nozzleDiameter: profile.nozzleDiameter,
    }));
    const payload: RegistryFile = {
      version: 1,
      defaultPrinter: this.defaultPrinterId,
      printers,
    };
    const temporaryPath = `${this.configPath}.${process.pid}.${Date.now()}.tmp`;
    try {
      fs.writeFileSync(temporaryPath, `${JSON.stringify(payload, null, 2)}\n`, {
        encoding: "utf8",
        mode: 0o600,
        flag: "wx",
      });
      fs.renameSync(temporaryPath, this.configPath);
      fs.chmodSync(this.configPath, 0o600);
    } finally {
      if (fs.existsSync(temporaryPath)) fs.rmSync(temporaryPath);
    }
  }
}
