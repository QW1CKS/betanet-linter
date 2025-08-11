export interface BinaryAnalysis {
    strings: string[];
    symbols: string[];
    sections: any[];
    headers: any;
}
export declare class BinaryAnalyzer {
    analyze(binaryPath: string): Promise<BinaryAnalysis>;
    extractStrings(binaryPath: string): Promise<string[]>;
    private extractStringsManually;
    extractSymbols(binaryPath: string): Promise<string[]>;
    extractSections(binaryPath: string): Promise<any[]>;
    extractHeaders(binaryPath: string): Promise<any>;
    private parseElfHeader;
    hasFunction(binaryPath: string, functionName: string): Promise<boolean>;
    hasLibraryDependency(binaryPath: string, libraryName: string): Promise<boolean>;
    getArchitecture(binaryPath: string): Promise<string>;
}
//# sourceMappingURL=binary-analyzer.d.ts.map