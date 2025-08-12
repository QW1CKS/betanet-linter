export interface ClientHelloStatic {
    alpn: string[];
    extOrderSha256?: string;
    detected: boolean;
    extensions?: number[];
    extensionNames?: string[];
}
export interface NoiseStatic {
    pattern?: string;
    messageCount?: number;
    detected: boolean;
}
export interface VoucherStatic {
    structLikely: boolean;
    tokenHits: string[];
    proximityBytes?: number;
}
export interface StaticPatterns {
    clientHello?: ClientHelloStatic;
    noise?: NoiseStatic;
    voucher?: VoucherStatic;
}
export declare function parseClientHelloStrings(strings: string[]): ClientHelloStatic | undefined;
export declare function detectNoisePattern(strings: string[]): NoiseStatic | undefined;
export declare function detectVoucherStruct(strings: string[], binary?: Buffer): VoucherStatic | undefined;
export declare function extractStaticPatterns(strings: string[], binary?: Buffer): StaticPatterns;
//# sourceMappingURL=static-parsers.d.ts.map