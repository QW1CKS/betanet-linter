export interface BinaryIntrospection {
    format: 'elf' | 'pe' | 'macho' | 'unknown';
    sections: string[];
    importsSample: string[];
    hasDebug: boolean;
    sizeBytes: number;
}
export declare function introspectBinary(binaryPath: string, extractedStrings: string[]): Promise<BinaryIntrospection>;
//# sourceMappingURL=binary-introspect.d.ts.map