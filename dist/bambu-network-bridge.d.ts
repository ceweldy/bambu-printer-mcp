type JsonObject = Record<string, unknown>;
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
export declare function defaultBambuNetworkConfigDir(): string;
export declare function requiresBambuNetworkProjectFileAcknowledgement(method: string): boolean;
export declare function isManagedBambuNetworkCallMethod(method: string): boolean;
export declare function isBambuNetworkControlMethod(method: string): boolean;
export declare function requiresBambuNetworkAgentForRawCall(method: string, withAgent: boolean | undefined): boolean;
export declare function createBambuNetworkSubmissionNames(projectName: string, taskName?: string): {
    projectName: string;
    taskName: string;
    nonce: string;
};
export declare function stageBambuNetworkCertificates(configDir: string, sourceDirectories: string[], strictSourceDirectory?: string): {
    certDir?: string;
    missing: string[];
    fingerprint?: string;
};
export declare function redactBambuNetworkDiagnostic(message: string): string;
export declare class BambuNetworkBridge {
    private child?;
    private commandLine?;
    private stdoutBuffer;
    private pending;
    private nextRequestId;
    private agentId?;
    private agentKey?;
    private handshake?;
    private lastStderr;
    private recentLogs;
    private inferredExpectedNetworkVersion?;
    private agentCertDir?;
    private lifecycleTail;
    private agentInitializationTail;
    private preservedEvents;
    private preservedControlEvents;
    private rawControlLaneOpen;
    private preserveEvents;
    private preserveControlEvents;
    withExclusiveLifecycle<T>(operation: () => Promise<T>, options?: {
        allowRawControl?: boolean;
    }): Promise<T>;
    isRawControlLaneOpen(): boolean;
    supportsProjectFileSequenceCorrelation(): boolean;
    private withAgentInitialization;
    resolveBridgeCommand(override?: string): string;
    resolveConfigDir(override?: string): string;
    resolveCountryCode(override?: string): string;
    private resolveCertificateSources;
    getStatus(options?: BambuNetworkBridgeOptions): BambuNetworkBridgeStatus;
    request(method: string, payload?: JsonObject, options?: BambuNetworkBridgeOptions): Promise<unknown>;
    requestControl(method: string, payload?: JsonObject, options?: BambuNetworkBridgeOptions): Promise<unknown>;
    ensureAgent(options?: BambuNetworkBridgeOptions): Promise<{
        agent: number;
        handshake: unknown;
    }>;
    private ensureAgentUnlocked;
    connectPrinter(connection: {
        devId: string;
        devIp: string;
        username: string;
        accessCode: string;
        useSsl: boolean;
    }, options?: BambuNetworkBridgeOptions): Promise<{
        connected: true;
        event: unknown;
        deviceCertificateRequested: boolean;
    }>;
    discardQueuedEvents(options?: BambuNetworkBridgeOptions): Promise<number>;
    pollEventsForControl(payload?: JsonObject, options?: BambuNetworkBridgeOptions): Promise<unknown>;
    waitForLocalPrintAcknowledgement(devId: string, expectedSequenceId: string, options?: BambuNetworkBridgeOptions): Promise<{
        errCode: number;
        command: string;
        sequenceId: string;
    }>;
    waitForPrinterJobStart(devId: string, expectedNames: string[], options?: BambuNetworkBridgeOptions): Promise<{
        state: string;
        filename: string;
    }>;
    callWithAgent(method: string, payload?: JsonObject, options?: BambuNetworkBridgeOptions): Promise<unknown>;
    stop(): Promise<void>;
    private ensureStarted;
    private handleStdout;
    private resolvePendingJson;
    private rememberLog;
    private rememberStderr;
    private rejectAllPending;
    private needsExpectedVersionRetry;
}
export {};
