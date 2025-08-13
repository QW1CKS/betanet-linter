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
    accessTicket?: AccessTicketStatic;
    voucherCrypto?: VoucherCryptoStatic;
}
export interface AccessTicketStatic {
    detected: boolean;
    fieldsPresent: string[];
    hex16Count?: number;
    hex32Count?: number;
    structConfidence?: number;
    rotationTokenPresent?: boolean;
    paddingLengths?: number[];
    paddingVariety?: number;
    rateLimitTokensPresent?: boolean;
}
export interface VoucherCryptoStatic {
    structLikely: boolean;
    keysetIdB64?: string;
    secretB64?: string;
    aggregatedSigB64?: string;
    signatureValid?: boolean;
    frostThreshold?: {
        n?: number;
        t?: number;
    };
}
export declare function parseClientHelloStrings(strings: string[]): ClientHelloStatic | undefined;
export declare function detectNoisePattern(strings: string[]): NoiseStatic | undefined;
export declare function detectVoucherStruct(strings: string[], binary?: Buffer): VoucherStatic | undefined;
export declare function extractStaticPatterns(strings: string[], binary?: Buffer): StaticPatterns;
//# sourceMappingURL=static-parsers.d.ts.map