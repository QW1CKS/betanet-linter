export interface SafeExecResult {
    stdout: string;
    stderr: string;
    code: number | null;
    signal: string | null;
    timedOut: boolean;
    failed: boolean;
    durationMs: number;
    start: number;
    errorMessage?: string;
}
export declare function isToolSkipped(tool: string): boolean;
export declare function safeExec(cmd: string, args?: string[], timeoutMs?: number): Promise<SafeExecResult>;
export declare function getConfiguredTimeout(): number;
//# sourceMappingURL=safe-exec.d.ts.map