import { BinaryAnalyzer } from '../src/analyzer';
import * as fs from 'fs';
import * as path from 'path';

describe('analyzer network retry exhaustion', () => {
  const tmpBin = path.join(__dirname,'net-bin.txt');
  beforeAll(()=>{ fs.writeFileSync(tmpBin,'net'); });
  afterAll(()=>{ try { fs.unlinkSync(tmpBin); } catch {} });

  it('retries then fails after max retries', async () => {
    const analyzer = new BinaryAnalyzer(tmpBin,false);
    analyzer.setNetworkAllowed(true,['example.com']);
    let attempts = 0;
    await expect(analyzer.attemptNetwork('https://example.com/data','GET', async () => { attempts++; throw new Error('always'); })).rejects.toThrow('always');
    expect(attempts).toBeGreaterThan(1);
    const diag = analyzer.getDiagnostics() as any;
    expect((diag.networkOps||[]).some((o:any)=>o.error==='always')).toBe(true);
  });
});
