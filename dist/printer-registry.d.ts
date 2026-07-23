export declare const SUPPORTED_BAMBU_MODELS: readonly ["p1s", "p1p", "p2s", "x1c", "x1e", "a1", "a1mini", "h2d", "h2s", "h2c"];
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
export declare class PrinterRegistry {
    private readonly env;
    private readonly configPath;
    private readonly ownsConfigDirectory;
    private readonly profiles;
    private readonly commandTails;
    private defaultPrinterId?;
    constructor(options?: RegistryOptions);
    get size(): number;
    get path(): string;
    has(id: string): boolean;
    private assertNoDuplicatePhysicalPrinter;
    targetId(id?: string): string;
    implicitReadyTargetId(): string | undefined;
    private load;
    private installProfiles;
    list(): PrinterProfileSummary[];
    private summarize;
    resolve(id?: string, overrides?: ResolveOverrides): ResolvedPrinterProfile;
    resolveAll(): {
        resolved: ResolvedPrinterProfile[];
        unavailable: PrinterProfileSummary[];
    };
    add(rawProfile: PrinterProfileInput, options?: {
        persist?: boolean;
        replace?: boolean;
    }): PrinterProfileSummary;
    remove(id: string, options?: {
        persist?: boolean;
    }): PrinterProfileSummary;
    setDefault(id: string, options?: {
        persist?: boolean;
    }): PrinterProfileSummary;
    runExclusive<T>(printerId: string, operation: () => Promise<T>): Promise<T>;
    private persist;
}
export {};
