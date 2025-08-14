import { BetanetComplianceChecker } from '../src/index';
import * as fs from 'fs';
import * as path from 'path';

describe('Task 28 environment lock ingestion', () => {
  const tmp = path.join(__dirname,'envlock-fixtures');
  const bin = path.join(tmp,'dummy.bin');
  beforeAll(()=>{ fs.mkdirSync(tmp,{recursive:true}); fs.writeFileSync(bin,'bin'); });
  afterAll(()=>{ try { fs.rmSync(tmp,{recursive:true,force:true}); } catch {} });

  it('ingests environment lock file and sets verified flag + diffCount=0 placeholder', async () => {
    const lock = { components:[{ name:'node', version:'20.10.0' },{ name:'npm', version:'10.5.0' }] };
    const lockFile = path.join(tmp,'env.lock.json'); fs.writeFileSync(lockFile, JSON.stringify(lock));
    const checker = new BetanetComplianceChecker();
    await checker.checkCompliance(bin,{ environmentLockFile: lockFile });
    const ev: any = (checker.analyzer as any).evidence;
    expect(ev.environmentLock).toBeDefined();
    expect(ev.environmentLock.verified).toBe(true);
    expect(ev.environmentLock.diffCount).toBe(0);
  }, 15000);
});
