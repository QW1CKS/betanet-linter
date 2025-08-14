import { extractStaticPatterns } from '../src/static-parsers';
import * as crypto from 'crypto';

describe('static parsers extra branches', () => {
  it('voucherCrypto aggregatedSigComputedValid path & access ticket padding variety', () => {
    const k = crypto.randomBytes(32); const sec = crypto.randomBytes(32);
    const h = crypto.createHash('sha256').update(Buffer.concat([k,sec])).digest();
    const sig = Buffer.concat([h.slice(0,16), Buffer.alloc(48)]);
    const b64k = k.toString('base64'); const b64s = sec.toString('base64'); const b64sig = sig.toString('base64');
    const strings = [
      'keysetid32','secret32','aggregatedsig64', b64k, b64s, b64sig,
      'ticket','nonce','pad16','pad_32','padding64','rotation','rl_bucket','frost n=5 t=3'
    ];
    const patterns = extractStaticPatterns(strings, Buffer.from('keysetid32...secret32...aggregatedsig64'));
    expect(patterns.voucherCrypto?.signatureValid).toBe(true);
    expect((patterns.accessTicket?.paddingVariety||0)).toBeGreaterThanOrEqual(3);
    expect(patterns.accessTicket?.rateLimitTokensPresent).toBe(true);
  });
});
