import * as fs from 'fs-extra';
import { BinaryAnalyzer } from './analyzer';

export interface HarnessOptions {
  scenarios?: string[]; // future expansion
  maxSeconds?: number;
  verbose?: boolean;
}

export interface HarnessEvidence {
  clientHello?: { alpn?: string[]; extOrderSha256?: string };
  noise?: { pattern?: string };
  voucher?: { structLikely?: boolean; tokenHits?: string[]; proximityBytes?: number };
  meta: { generated: string; scenarios: string[] };
}

export async function runHarness(binaryPath: string, outFile: string, opts: HarnessOptions = {}): Promise<string> {
  const analyzer = new BinaryAnalyzer(binaryPath, !!opts.verbose);
  const patterns = await analyzer.getStaticPatterns();
  const evidence: HarnessEvidence = {
    clientHello: patterns.clientHello ? { alpn: patterns.clientHello.alpn, extOrderSha256: patterns.clientHello.extOrderSha256 } : undefined,
    noise: patterns.noise ? { pattern: patterns.noise.pattern } : undefined,
    voucher: patterns.voucher ? { structLikely: patterns.voucher.structLikely, tokenHits: patterns.voucher.tokenHits, proximityBytes: patterns.voucher.proximityBytes } : undefined,
    meta: { generated: new Date().toISOString(), scenarios: opts.scenarios || [] }
  };
  await fs.writeFile(outFile, JSON.stringify(evidence, null, 2));
  return outFile;
}
