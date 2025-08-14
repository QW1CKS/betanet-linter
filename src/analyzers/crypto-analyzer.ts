// Removed unused fs import (lint cleanup)
import execa from 'execa';

export interface CryptoAnalysis {
  ciphers: string[];
  hashes: string[];
  signatures: string[];
  keyExchange: string[];
  postQuantum: boolean;
  hasChaCha20: boolean;
  hasEd25519: boolean;
  hasX25519: boolean;
  hasKyber: boolean;
  libraries: string[];
}

export class CryptoAnalyzer {
  async analyze(binaryPath: string): Promise<CryptoAnalysis> {
    const [ciphers, hashes, signatures, keyExchange, libraries] = await Promise.all([
      this.detectCiphers(binaryPath),
      this.detectHashes(binaryPath),
      this.detectSignatures(binaryPath),
      this.detectKeyExchange(binaryPath),
      this.detectCryptoLibraries(binaryPath)
    ]);

    const postQuantum = ciphers.some(c => c.toLowerCase().includes('kyber')) ||
                       keyExchange.some(k => k.toLowerCase().includes('kyber'));
    
    const hasChaCha20 = ciphers.some(c => 
      c.toLowerCase().includes('chacha20') || 
      c.toLowerCase().includes('chacha')
    );
    
    const hasEd25519 = signatures.some(s => 
      s.toLowerCase().includes('ed25519') || 
      s.toLowerCase().includes('eddsa')
    );
    
    const hasX25519 = keyExchange.some(k => 
      k.toLowerCase().includes('x25519') || 
      k.toLowerCase().includes('curve25519')
    );
    
    const hasKyber = ciphers.some(c => c.toLowerCase().includes('kyber')) ||
                     keyExchange.some(k => k.toLowerCase().includes('kyber'));

    return {
      ciphers,
      hashes,
      signatures,
      keyExchange,
      postQuantum,
      hasChaCha20,
      hasEd25519,
      hasX25519,
      hasKyber,
      libraries
    };
  }

  async detectCiphers(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const ciphers: string[] = [];

      // Betanet specification ciphers
      const specCiphers = [
        'ChaCha20-Poly1305',
        'AES_256_GCM',
        'AES_128_GCM',
        'X25519-Kyber768',
        'AES_256_CBC',
        'AES_128_CBC'
      ];

      // Common cipher patterns
      const cipherPatterns = [
        /ChaCha20[_-]?Poly1305/i,
        /AES[_-]?\d{3}[_-]?(GCM|CBC)/i,
        /X25519[_-]?Kyber768/i,
        /Kyber768/i,
        /ECDHE[_-]?RSA/i,
        /ECDHE[_-]?ECDSA/i,
        /RSA[_-]?\w+/i,
        /ECDSA[_-]?\w+/i
      ];

      // Check for spec ciphers first
      specCiphers.forEach(cipher => {
        if (stdout.includes(cipher)) {
          ciphers.push(cipher);
        }
      });

      // Check for pattern matches
      cipherPatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          ciphers.push(...matches);
        }
      });

      return [...new Set(ciphers)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectHashes(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const hashes: string[] = [];

      // Betanet specification hashes
      const specHashes = [
        'SHA-256',
        'SHA256',
        'SHA-512',
        'SHA512',
        'BLAKE2',
        'BLAKE3'
      ];

      // Hash patterns
      const hashPatterns = [
        /SHA[_-]?\d{3}/i,
        /SHA\d{3}/i,
        /BLAKE[23]?/i,
        /MD5/i,
        /RIPEMD[_-]?\d+/i
      ];

      // Check for spec hashes first
      specHashes.forEach(hash => {
        if (stdout.includes(hash)) {
          hashes.push(hash);
        }
      });

      // Check for pattern matches
      hashPatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          hashes.push(...matches);
        }
      });

      return [...new Set(hashes)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectSignatures(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const signatures: string[] = [];

      // Betanet specification signatures
      const specSignatures = [
        'Ed25519',
        'EdDSA',
        'ECDSA',
        'RSA',
        'RSA-PSS'
      ];

      // Signature patterns
      const signaturePatterns = [
        /Ed25519/i,
        /EdDSA/i,
        /ECDSA/i,
        /RSA[_-]?PSS/i,
        /RSA[_-]?\w+/i,
        /DSA/i
      ];

      // Check for spec signatures first
      specSignatures.forEach(sig => {
        if (stdout.includes(sig)) {
          signatures.push(sig);
        }
      });

      // Check for pattern matches
      signaturePatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          signatures.push(...matches);
        }
      });

      return [...new Set(signatures)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectKeyExchange(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const keyExchange: string[] = [];

      // Betanet specification key exchange
      const specKeyExchange = [
        'X25519',
        'Curve25519',
        'X25519-Kyber768',
        'Kyber768',
        'ECDH',
        'DH'
      ];

      // Key exchange patterns
      const kexPatterns = [
        /X25519/i,
        /Curve25519/i,
        /X25519[_-]?Kyber768/i,
        /Kyber768/i,
        /ECDH[_-]?\w+/i,
        /ECDHE/i,
        /DH[_-]?\w+/i
      ];

      // Check for spec key exchange first
      specKeyExchange.forEach(kex => {
        if (stdout.includes(kex)) {
          keyExchange.push(kex);
        }
      });

      // Check for pattern matches
      kexPatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          keyExchange.push(...matches);
        }
      });

      return [...new Set(keyExchange)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectCryptoLibraries(binaryPath: string): Promise<string[]> {
    try {
      const { stdout } = await execa('ldd', [binaryPath]);
      const libraries: string[] = [];

      // Common crypto libraries
      const cryptoLibs = [
        'libssl',
        'libcrypto',
        'libgcrypt',
        'libnettle',
        'libhogweed',
        'libgmp',
        'libsodium',
        'libhydrogen',
        'liboqs',
        'libpqcrypto'
      ];

      cryptoLibs.forEach(lib => {
        if (stdout.toLowerCase().includes(lib)) {
          libraries.push(lib);
        }
      });

      // Also check strings for crypto library references
      const { stdout: stringsOut } = await execa('strings', [binaryPath]);
      const libPatterns = [
        /OpenSSL/i,
        /BoringSSL/i,
        /LibreSSL/i,
        /libsodium/i,
        /NaCl/i,
        /OQS/i,
        /PQCrypto/i
      ];

      libPatterns.forEach(pattern => {
        const matches = stringsOut.match(pattern);
        if (matches) {
          libraries.push(...matches);
        }
      });

      return [...new Set(libraries)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async hasBetanetCryptoSuite(binaryPath: string): Promise<boolean> {
    const analysis = await this.analyze(binaryPath);
    
    // Check for required Betanet crypto primitives
    const hasSHA256 = analysis.hashes.some(h => 
      h.toLowerCase().includes('sha256')
    );
    
    const hasChaCha20Poly1305 = analysis.ciphers.some(c => 
      c.toLowerCase().includes('chacha20') && 
      c.toLowerCase().includes('poly1305')
    );
    
    const hasEd25519 = analysis.hasEd25519;
    const hasX25519 = analysis.hasX25519;

    return hasSHA256 && hasChaCha20Poly1305 && hasEd25519 && hasX25519;
  }

  async hasPostQuantumSupport(binaryPath: string): Promise<boolean> {
    const analysis = await this.analyze(binaryPath);
    return analysis.postQuantum || analysis.hasKyber;
  }

  async getCryptoComplianceScore(binaryPath: string): Promise<number> {
    const analysis = await this.analyze(binaryPath);
    
    let score = 0;
    const maxScore = 100;

    // Required algorithms (40 points)
    if (analysis.hashes.some(h => h.toLowerCase().includes('sha256'))) score += 10;
    if (analysis.hasChaCha20) score += 15;
    if (analysis.hasEd25519) score += 10;
    if (analysis.hasX25519) score += 5;

    // Post-quantum support (30 points)
    if (analysis.hasKyber) score += 30;

    // Additional features (30 points)
    if (analysis.libraries.length > 0) score += 10;
    if (analysis.ciphers.length > 3) score += 10;
    if (analysis.signatures.length > 2) score += 10;

    return Math.min(score, maxScore);
  }
}