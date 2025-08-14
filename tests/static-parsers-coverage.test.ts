import { parseClientHelloStrings, detectNoisePattern, detectVoucherStruct, extractStaticPatterns } from '../src/static-parsers';

describe('static parsers coverage', () => {
  it('parses client hello extensions and ALPN ordering', () => {
    const strings = ['h2','http/1.1','server_name','supported_groups','key_share'];
    const ch = parseClientHelloStrings(strings)!;
    expect(ch.alpn).toContain('h2');
    expect(ch.extensions && ch.extensions.length).toBeGreaterThan(0);
    expect(ch.extOrderSha256).toHaveLength(64);
  });

  it('detects noise pattern direct token', () => {
    const n = detectNoisePattern(['Noise_XK']);
    expect(n?.pattern).toBe('XK');
  });

  it('detects noise pattern indirect', () => {
    const n = detectNoisePattern(['noise handshake','token','XK']);
    expect(n?.pattern).toBe('XK');
  });

  it('detects voucher struct and crypto fields', () => {
    const strings = ['keysetid32','secret32','aggregatedsig64','AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=','BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=','CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC'];
    const binary = Buffer.from('keysetid32....secret32....aggregatedsig64');
    const voucher = detectVoucherStruct(strings, binary)!;
    expect(voucher.structLikely).toBe(true);
  });

  it('extracts composite static patterns', () => {
    const strings = ['h2','http/1.1','server_name','Noise_XK','keysetid32','secret32','aggregatedsig64','ticket','nonce'];
    const binary = Buffer.from('keysetid32secret32aggregatedsig64');
    const patterns = extractStaticPatterns(strings, binary);
    expect(patterns.clientHello?.detected).toBe(true);
    expect(patterns.noise?.detected).toBe(true);
    expect(patterns.voucher?.structLikely).toBe(true);
  });
});
