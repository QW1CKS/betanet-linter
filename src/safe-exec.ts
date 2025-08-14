import execa from 'execa';

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

const DEFAULT_TIMEOUT_MS = parseInt(process.env.BETANET_TOOL_TIMEOUT_MS || '5000', 10);
export function isToolSkipped(tool: string): boolean {
  const skip = (process.env.BETANET_SKIP_TOOLS || '')
    .split(',')
    .map(s => s.trim())
    .filter(Boolean);
  return skip.includes(tool);
}

export async function safeExec(cmd: string, args: string[] = [], timeoutMs?: number): Promise<SafeExecResult> {
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
    const child = await execa(cmd, args, {
      timeout: timeoutMs || DEFAULT_TIMEOUT_MS,
      reject: false // handle failures uniformly
    });
    const timedOut = (child as any).timedOut === true;
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
      errorMessage: failed ? (timedOut ? 'timeout' : child.stderr || (child as any).shortMessage || 'non-zero-exit') : undefined
    };
  } catch (e: unknown) {
    // External process errors can include non-Error enriched fields (timedOut, exitCode, stdout, shortMessage)
    const err = e as any; // narrowed locally; safeExec returns normalized object
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

export function getConfiguredTimeout(): number {
  return DEFAULT_TIMEOUT_MS;
}
