"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.isToolSkipped = isToolSkipped;
exports.safeExec = safeExec;
exports.getConfiguredTimeout = getConfiguredTimeout;
const execa_1 = __importDefault(require("execa"));
const DEFAULT_TIMEOUT_MS = parseInt(process.env.BETANET_TOOL_TIMEOUT_MS || '5000', 10);
function isToolSkipped(tool) {
    const skip = (process.env.BETANET_SKIP_TOOLS || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean);
    return skip.includes(tool);
}
async function safeExec(cmd, args = [], timeoutMs) {
    const start = Date.now();
    if (isToolSkipped(cmd)) {
        return {
            stdout: '',
            stderr: '',
            code: null,
            signal: null,
            timedOut: false,
            failed: true,
            durationMs: Date.now() - start,
            start,
            errorMessage: 'skipped-by-config'
        };
    }
    try {
        const child = await (0, execa_1.default)(cmd, args, {
            timeout: timeoutMs || DEFAULT_TIMEOUT_MS,
            reject: false // handle failures uniformly
        });
        const timedOut = child.timedOut === true;
        const failed = timedOut || child.exitCode !== 0;
        return {
            stdout: child.stdout || '',
            stderr: child.stderr || '',
            code: child.exitCode,
            signal: child.signal || null,
            timedOut,
            failed,
            durationMs: Date.now() - start,
            start,
            errorMessage: failed ? (timedOut ? 'timeout' : child.stderr || child.shortMessage || 'non-zero-exit') : undefined
        };
    }
    catch (e) {
        // External process errors can include non-Error enriched fields (timedOut, exitCode, stdout, shortMessage)
        const err = e; // narrowed locally; safeExec returns normalized object
        const timedOut = err?.timedOut === true;
        return {
            stdout: err?.stdout || '',
            stderr: err?.stderr || '',
            code: err?.exitCode ?? null,
            signal: err?.signal || null,
            timedOut,
            failed: true,
            durationMs: Date.now() - start,
            start,
            errorMessage: timedOut ? 'timeout' : (err?.shortMessage || err?.message || 'exec-error')
        };
    }
}
function getConfiguredTimeout() {
    return DEFAULT_TIMEOUT_MS;
}
//# sourceMappingURL=safe-exec.js.map