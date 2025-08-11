"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.BinaryAnalyzer = void 0;
const fs = __importStar(require("fs-extra"));
const execa_1 = __importDefault(require("execa"));
class BinaryAnalyzer {
    async analyze(binaryPath) {
        const [strings, symbols, sections, headers] = await Promise.all([
            this.extractStrings(binaryPath),
            this.extractSymbols(binaryPath),
            this.extractSections(binaryPath),
            this.extractHeaders(binaryPath)
        ]);
        return {
            strings,
            symbols,
            sections,
            headers
        };
    }
    async extractStrings(binaryPath) {
        try {
            // Try using 'strings' command first
            const { stdout } = await (0, execa_1.default)('strings', [binaryPath]);
            return stdout.split('\n').filter((s) => s.length > 0);
        }
        catch (error) {
            // Fallback to manual string extraction
            console.warn('strings command not available, using fallback method');
            return this.extractStringsManually(binaryPath);
        }
    }
    async extractStringsManually(binaryPath) {
        const buffer = await fs.readFile(binaryPath);
        const strings = [];
        let currentString = '';
        for (let i = 0; i < buffer.length; i++) {
            const byte = buffer[i];
            // Printable ASCII characters
            if (byte >= 32 && byte <= 126) {
                currentString += String.fromCharCode(byte);
            }
            else {
                // End of string
                if (currentString.length >= 4) { // Minimum string length
                    strings.push(currentString);
                }
                currentString = '';
            }
        }
        // Check for string at the end
        if (currentString.length >= 4) {
            strings.push(currentString);
        }
        return strings;
    }
    async extractSymbols(binaryPath) {
        try {
            // Try using 'nm' command for symbols
            const { stdout } = await (0, execa_1.default)('nm', [binaryPath]);
            return stdout.split('\n')
                .filter((line) => line.trim())
                .map((line) => {
                const parts = line.split(/\s+/);
                return parts[parts.length - 1]; // Symbol name is usually the last part
            })
                .filter((symbol) => symbol && symbol.length > 0);
        }
        catch (error) {
            // Fallback: return empty array
            return [];
        }
    }
    async extractSections(binaryPath) {
        try {
            // Try using 'objdump' for sections
            const { stdout } = await (0, execa_1.default)('objdump', ['-h', binaryPath]);
            const lines = stdout.split('\n');
            const sections = [];
            for (const line of lines) {
                if (line.match(/^\s*\d+\s+\.\w+/)) {
                    const parts = line.trim().split(/\s+/);
                    if (parts.length >= 6) {
                        sections.push({
                            name: parts[1],
                            size: parts[2],
                            vma: parts[3],
                            lma: parts[4],
                            fileoff: parts[5],
                            align: parts[6]
                        });
                    }
                }
            }
            return sections;
        }
        catch (error) {
            return [];
        }
    }
    async extractHeaders(binaryPath) {
        try {
            // Try using 'file' command for basic file info
            const { stdout } = await (0, execa_1.default)('file', [binaryPath]);
            // Try using 'readelf' for ELF headers
            let elfInfo = {};
            try {
                const { stdout: elfOutput } = await (0, execa_1.default)('readelf', ['-h', binaryPath]);
                elfInfo = this.parseElfHeader(elfOutput);
            }
            catch (e) {
                // Not an ELF file or readelf not available
            }
            return {
                fileType: stdout,
                elf: elfInfo
            };
        }
        catch (error) {
            return {
                fileType: 'Unknown',
                elf: {}
            };
        }
    }
    parseElfHeader(output) {
        const lines = output.split('\n');
        const header = {};
        for (const line of lines) {
            const match = line.match(/^\s*(.+?):\s*(.+)$/);
            if (match) {
                const key = match[1].trim().replace(/\s+/g, '_').toLowerCase();
                const value = match[2].trim();
                header[key] = value;
            }
        }
        return header;
    }
    async hasFunction(binaryPath, functionName) {
        const symbols = await this.extractSymbols(binaryPath);
        return symbols.some(symbol => symbol.includes(functionName) ||
            symbol.toLowerCase().includes(functionName.toLowerCase()));
    }
    async hasLibraryDependency(binaryPath, libraryName) {
        try {
            const { stdout } = await (0, execa_1.default)('ldd', [binaryPath]);
            return stdout.toLowerCase().includes(libraryName.toLowerCase());
        }
        catch (error) {
            return false;
        }
    }
    async getArchitecture(binaryPath) {
        try {
            const { stdout } = await (0, execa_1.default)('file', [binaryPath]);
            const archMatch = stdout.match(/(x86_64|i386|arm64|arm|aarch64)/i);
            return archMatch ? archMatch[1].toLowerCase() : 'unknown';
        }
        catch (error) {
            return 'unknown';
        }
    }
}
exports.BinaryAnalyzer = BinaryAnalyzer;
//# sourceMappingURL=binary-analyzer.js.map