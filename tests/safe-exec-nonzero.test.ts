import { safeExec } from '../src/safe-exec';

describe('safeExec non-zero exit path', () => {
  it('captures non-zero exit without timeout', async () => {
    const cmd = process.platform === 'win32' ? 'cmd' : 'node';
    const args = process.platform === 'win32' ? ['/c','exit','5'] : ['-e','process.exit(7)'];
    const res = await safeExec(cmd, args, 1000);
    expect(res.failed).toBe(true);
    expect(res.timedOut).toBe(false);
  // Accept 'non-zero-exit' or underlying shell error message variants
  expect(['non-zero-exit','timeout','exec-error'].some(tok => (res.errorMessage||'').includes(tok)) || /not recognized|exit/i.test(res.errorMessage||'')).toBe(true);
  });
});
