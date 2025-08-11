import * as fs from 'fs-extra';
import execa from 'execa';

export interface NetworkAnalysis {
  protocols: string[];
  ports: number[];
  endpoints: string[];
  certificates: any[];
  tlsConfig: any;
}

export class NetworkAnalyzer {
  async analyze(binaryPath: string): Promise<NetworkAnalysis> {
    const [protocols, ports, endpoints, certificates, tlsConfig] = await Promise.all([
      this.detectProtocols(binaryPath),
      this.detectPorts(binaryPath),
      this.detectEndpoints(binaryPath),
      this.detectCertificates(binaryPath),
      this.analyzeTLSConfig(binaryPath)
    ]);

    return {
      protocols,
      ports,
      endpoints,
      certificates,
      tlsConfig
    };
  }

  async detectProtocols(binaryPath: string): Promise<string[]> {
    try {
      const buffer = await fs.readFile(binaryPath);
      const content = buffer.toString('latin1');
      const protocols: string[] = [];

      // Check for common protocol signatures
      const protocolSignatures = {
        'HTTP': ['HTTP/', 'http://', 'https://'],
        'QUIC': ['QUIC', 'quic'],
        'TLS': ['TLS', 'SSL', 'certificate'],
        'TCP': ['TCP', 'tcp'],
        'UDP': ['UDP', 'udp'],
        'WebSocket': ['websocket', 'ws://', 'wss://'],
        'gRPC': ['grpc', 'HTTP/2'],
        'HTX': ['htx', '/betanet/htx'],
        'SCION': ['scion', 'SCION']
      };

      for (const [protocol, signatures] of Object.entries(protocolSignatures)) {
        if (signatures.some(sig => content.toLowerCase().includes(sig.toLowerCase()))) {
          protocols.push(protocol);
        }
      }

      return [...new Set(protocols)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectPorts(binaryPath: string): Promise<number[]> {
    try {
      const buffer = await fs.readFile(binaryPath);
      const content = buffer.toString('latin1');
      const ports: number[] = [];

      // Look for common port numbers
      const portRegex = /\b(443|80|8443|8080|3000|5000|9000)\b/g;
      const matches = content.match(portRegex);
      
      if (matches) {
        matches.forEach(match => {
          const port = parseInt(match);
          if (!ports.includes(port)) {
            ports.push(port);
          }
        });
      }

      return ports;
    } catch (error) {
      return [];
    }
  }

  async detectEndpoints(binaryPath: string): Promise<string[]> {
    try {
      const buffer = await fs.readFile(binaryPath);
      const content = buffer.toString('latin1');
      const endpoints: string[] = [];

      // Look for URL patterns and endpoints
      const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/g;
      const endpointRegex = /\/[a-zA-Z0-9\-_\/]+/g;

      const urlMatches = content.match(urlRegex);
      const endpointMatches = content.match(endpointRegex);

      if (urlMatches) {
        endpoints.push(...urlMatches);
      }

      if (endpointMatches) {
        endpoints.push(...endpointMatches);
      }

      // Filter for Betanet-specific endpoints
      const betanetEndpoints = endpoints.filter(endpoint => 
        endpoint.includes('/betanet/') || 
        endpoint.includes('htx') ||
        endpoint.includes('htxquic')
      );

      return [...new Set(betanetEndpoints)]; // Remove duplicates
    } catch (error) {
      return [];
    }
  }

  async detectCertificates(binaryPath: string): Promise<any[]> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const certificates: any[] = [];

      // Look for certificate-related strings
      const certPatterns = [
        /-----BEGIN CERTIFICATE-----/,
        /-----BEGIN PRIVATE KEY-----/,
        /-----BEGIN PUBLIC KEY-----/,
        /subject=.*?CN=([^,\s]+)/,
        /issuer=.*?CN=([^,\s]+)/
      ];

      const lines = stdout.split('\n');
      let currentCert = '';
      let inCertBlock = false;

      for (const line of lines) {
        if (line.includes('-----BEGIN CERTIFICATE-----')) {
          inCertBlock = true;
          currentCert = line;
        } else if (line.includes('-----END CERTIFICATE-----')) {
          inCertBlock = false;
          currentCert += '\n' + line;
          certificates.push({
            type: 'certificate',
            data: currentCert,
            length: currentCert.length
          });
          currentCert = '';
        } else if (inCertBlock) {
          currentCert += '\n' + line;
        }

        // Look for certificate info in strings
        for (const pattern of certPatterns) {
          const match = line.match(pattern);
          if (match) {
            certificates.push({
              type: 'certificate_info',
              info: match[0],
              line: line
            });
          }
        }
      }

      return certificates;
    } catch (error) {
      return [];
    }
  }

  async analyzeTLSConfig(binaryPath: string): Promise<any> {
    try {
      const { stdout } = await execa('strings', [binaryPath]);
      const tlsConfig: any = {
        versions: [],
        ciphers: [],
        extensions: [],
        hasECH: false,
        hasTLS13: false
      };

      // Check for TLS versions
      const tlsVersions = ['TLSv1.3', 'TLSv1.2', 'TLSv1.1', 'TLSv1.0', 'SSLv3', 'SSLv2'];
      tlsVersions.forEach(version => {
        if (stdout.includes(version)) {
          tlsConfig.versions.push(version);
          if (version === 'TLSv1.3') {
            tlsConfig.hasTLS13 = true;
          }
        }
      });

      // Check for cipher suites
      const cipherPatterns = [
        /AES_128_GCM/,
        /AES_256_GCM/,
        /ChaCha20_Poly1305/,
        /ECDHE_RSA/,
        /ECDHE_ECDSA/,
        /TLS_AES_128_GCM/,
        /TLS_AES_256_GCM/,
        /TLS_CHACHA20_POLY1305/
      ];

      cipherPatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          tlsConfig.ciphers.push(...matches);
        }
      });

      // Check for TLS extensions
      const extensionPatterns = [
        /server_name/,
        /supported_groups/,
        /signature_algorithms/,
        /encrypted_client_hello/,
        /ECH/
      ];

      extensionPatterns.forEach(pattern => {
        const matches = stdout.match(pattern);
        if (matches) {
          tlsConfig.extensions.push(...matches);
          if (pattern.toString().includes('ECH')) {
            tlsConfig.hasECH = true;
          }
        }
      });

      return tlsConfig;
    } catch (error) {
      return {
        versions: [],
        ciphers: [],
        extensions: [],
        hasECH: false,
        hasTLS13: false,
  error: (error as any)?.message
      };
    }
  }

  async supportsHTX(binaryPath: string): Promise<boolean> {
    const analysis = await this.analyze(binaryPath);
    return analysis.protocols.includes('HTX') || 
           analysis.endpoints.some(e => e.includes('/betanet/htx'));
  }

  async supportsQUIC(binaryPath: string): Promise<boolean> {
    const analysis = await this.analyze(binaryPath);
    return analysis.protocols.includes('QUIC') && 
           analysis.ports.includes(443);
  }

  async hasTLS13WithECH(binaryPath: string): Promise<boolean> {
    const analysis = await this.analyze(binaryPath);
    return analysis.tlsConfig.hasTLS13 && analysis.tlsConfig.hasECH;
  }
}