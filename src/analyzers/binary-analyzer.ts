import * as fs from 'fs-extra';
import * as path from 'path';
import execa from 'execa';

export interface BinaryAnalysis {
  strings: string[];
  symbols: string[];
  sections: any[];
  headers: any;
}

export class BinaryAnalyzer {
  async analyze(binaryPath: string): Promise<BinaryAnalysis> {
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

  async extractStrings(binaryPath: string): Promise<string[]> {
    try {
      // Try using 'strings' command first
      const { stdout } = await execa('strings', [binaryPath]);
  return stdout.split('\n').filter((s: string) => s.length > 0);
    } catch (error) {
      // Fallback to manual string extraction
      console.warn('strings command not available, using fallback method');
      return this.extractStringsManually(binaryPath);
    }
  }

  private async extractStringsManually(binaryPath: string): Promise<string[]> {
    const buffer = await fs.readFile(binaryPath);
    const strings: string[] = [];
    let currentString = '';

    for (let i = 0; i < buffer.length; i++) {
      const byte = buffer[i];
      
      // Printable ASCII characters
      if (byte >= 32 && byte <= 126) {
        currentString += String.fromCharCode(byte);
      } else {
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

  async extractSymbols(binaryPath: string): Promise<string[]> {
    try {
      // Try using 'nm' command for symbols
      const { stdout } = await execa('nm', [binaryPath]);
      return stdout.split('\n')
        .filter((line: string) => line.trim())
        .map((line: string) => {
          const parts = line.split(/\s+/);
          return parts[parts.length - 1]; // Symbol name is usually the last part
        })
        .filter((symbol: string) => symbol && symbol.length > 0);
    } catch (error) {
      // Fallback: return empty array
      return [];
    }
  }

  async extractSections(binaryPath: string): Promise<any[]> {
    try {
      // Try using 'objdump' for sections
      const { stdout } = await execa('objdump', ['-h', binaryPath]);
      const lines = stdout.split('\n');
      const sections: any[] = [];

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
    } catch (error) {
      return [];
    }
  }

  async extractHeaders(binaryPath: string): Promise<any> {
    try {
      // Try using 'file' command for basic file info
      const { stdout } = await execa('file', [binaryPath]);
      
      // Try using 'readelf' for ELF headers
      let elfInfo = {};
      try {
        const { stdout: elfOutput } = await execa('readelf', ['-h', binaryPath]);
        elfInfo = this.parseElfHeader(elfOutput);
      } catch (e) {
        // Not an ELF file or readelf not available
      }

      return {
        fileType: stdout,
        elf: elfInfo
      };
    } catch (error) {
      return {
        fileType: 'Unknown',
        elf: {}
      };
    }
  }

  private parseElfHeader(output: string): any {
    const lines = output.split('\n');
    const header: any = {};

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

  async hasFunction(binaryPath: string, functionName: string): Promise<boolean> {
    const symbols = await this.extractSymbols(binaryPath);
    return symbols.some(symbol => 
      symbol.includes(functionName) || 
      symbol.toLowerCase().includes(functionName.toLowerCase())
    );
  }

  async hasLibraryDependency(binaryPath: string, libraryName: string): Promise<boolean> {
    try {
      const { stdout } = await execa('ldd', [binaryPath]);
      return stdout.toLowerCase().includes(libraryName.toLowerCase());
    } catch (error) {
      return false;
    }
  }

  async getArchitecture(binaryPath: string): Promise<string> {
    try {
      const { stdout } = await execa('file', [binaryPath]);
      const archMatch = stdout.match(/(x86_64|i386|arm64|arm|aarch64)/i);
      return archMatch ? archMatch[1].toLowerCase() : 'unknown';
    } catch (error) {
      return 'unknown';
    }
  }
}