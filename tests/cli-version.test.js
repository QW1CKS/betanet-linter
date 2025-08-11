const { execSync } = require('child_process');

describe('CLI --version and version command', () => {
  it('prints version and exits 0 (flag)', () => {
    const out = execSync('node bin/cli.js --version').toString().trim();
    expect(out).toMatch(/^\d+\.\d+\.\d+$/);
  });
  it('prints version and exits 0 (command)', () => {
    const out = execSync('node bin/cli.js version').toString().trim();
    expect(out).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
