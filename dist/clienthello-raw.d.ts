export interface ParsedRawClientHello {
    version?: number;
    ciphers: number[];
    extensions: number[];
    groups: number[];
    ecPointFormats: number[];
    ja3: string;
    ja3Hash: string;
}
export declare function parseRawClientHello(buf: Buffer): ParsedRawClientHello;
export declare function detectGrease(extensions: number[]): {
    greasePresent: boolean;
    greaseValues: number[];
};
//# sourceMappingURL=clienthello-raw.d.ts.map