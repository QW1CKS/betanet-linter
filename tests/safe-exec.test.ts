import { safeExec, isToolSkipped, getConfiguredTimeout } from '../src/safe-exec';

describe('safeExec utility', () => {
  it('skips tool via env config', async () => {
    process.env.BETANET_SKIP_TOOLS = 'echo';
    const res = await safeExec('echo',['hi']);
    expect(res.failed).toBe(true);
    expect(res.errorMessage).toBe('skipped-by-config');
  });

  it('executes a simple command', async () => {
  process.env.BETANET_SKIP_TOOLS = '';
  // Use node itself for a cross-platform reliable command to eliminate console.warn noise on platforms
  const res = await safeExec(process.execPath, ['-e', 'console.log("hello")']);
  expect(res.failed).toBe(false);
  expect(res.stdout.toLowerCase()).toContain('hello');
  });

  it('handles timeout', async () => {
    // Use a command that sleeps longer than timeout; platform dependent
    const cmd = process.platform === 'win32' ? 'ping' : 'sleep';
    const args = process.platform === 'win32' ? ['127.0.0.1','-n','6'] : ['5'];
    const res = await safeExec(cmd, args, 10); // 10ms timeout
    expect(res.failed).toBe(true);
    expect(res.timedOut || res.errorMessage === 'timeout').toBe(true);
  });

  it('reports configured timeout', () => {
    expect(getConfiguredTimeout()).toBeGreaterThan(0);
  });
});
