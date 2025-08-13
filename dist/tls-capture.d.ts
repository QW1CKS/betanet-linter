export interface CanonicalClientHello {
    ja3: string;
    ja3Hash: string;
    ja3Canonical?: string;
    rawSynthetic?: Buffer;
    rawCanonical?: Buffer;
    extensions: number[];
    ciphers: number[];
    curves: number[];
    ecPointFormats: number[];
}
export declare function buildCanonicalClientHello(struct: {
    extensions: number[];
    ciphers: number[];
    curves?: number[];
    alpn?: string[];
    host?: string;
    seedHash?: string;
}): CanonicalClientHello;
//# sourceMappingURL=tls-capture.d.ts.map