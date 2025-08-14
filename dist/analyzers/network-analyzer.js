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
Object.defineProperty(exports, "__esModule", { value: true });
exports.NetworkAnalyzer = void 0;
const fs = __importStar(require("fs-extra"));
const safe_exec_1 = require("../safe-exec");
class NetworkAnalyzer {
    async analyze(binaryPath) {
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
    async detectProtocols(binaryPath) {
        try {
            const buffer = await fs.readFile(binaryPath);
            const content = buffer.toString('latin1');
            const protocols = [];
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
        }
        catch (error) {
            return [];
        }
    }
    async detectPorts(binaryPath) {
        try {
            const buffer = await fs.readFile(binaryPath);
            const content = buffer.toString('latin1');
            const ports = [];
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
        }
        catch (error) {
            return [];
        }
    }
    async detectEndpoints(binaryPath) {
        try {
            const buffer = await fs.readFile(binaryPath);
            const content = buffer.toString('latin1');
            const endpoints = [];
            // Look for URL patterns and endpoints
            // eslint-disable-next-line no-useless-escape -- backslash before / is required to represent literal slash at start
            const urlRegex = /https?:\/\/[^\s<>"'{}|\\^`[\]]+/g; // Removed unnecessary escape for '['; keep escaped ] & \
            const endpointRegex = /\/[\w/-]+/g; // Removed unnecessary escape for '/' inside character class
            const urlMatches = content.match(urlRegex);
            const endpointMatches = content.match(endpointRegex);
            if (urlMatches) {
                endpoints.push(...urlMatches);
            }
            if (endpointMatches) {
                endpoints.push(...endpointMatches);
            }
            // Filter for Betanet-specific endpoints
            const betanetEndpoints = endpoints.filter(endpoint => endpoint.includes('/betanet/') ||
                endpoint.includes('htx') ||
                endpoint.includes('htxquic'));
            return [...new Set(betanetEndpoints)]; // Remove duplicates
        }
        catch (error) {
            return [];
        }
    }
    async detectCertificates(binaryPath) {
        try {
            const res = await (0, safe_exec_1.safeExec)('strings', [binaryPath], 4000);
            const stdout = res.failed ? '' : res.stdout;
            const certificates = [];
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
                }
                else if (line.includes('-----END CERTIFICATE-----')) {
                    inCertBlock = false;
                    currentCert += '\n' + line;
                    certificates.push({
                        type: 'certificate',
                        data: currentCert,
                        length: currentCert.length
                    });
                    currentCert = '';
                }
                else if (inCertBlock) {
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
        }
        catch (error) {
            return [];
        }
    }
    async analyzeTLSConfig(binaryPath) {
        try {
            const res = await (0, safe_exec_1.safeExec)('strings', [binaryPath], 4000);
            const stdout = res.failed ? '' : res.stdout;
            const tlsConfig = {
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
        }
        catch (error) {
            return {
                versions: [],
                ciphers: [],
                extensions: [],
                hasECH: false,
                hasTLS13: false,
                error: error?.message
            };
        }
    }
    async supportsHTX(binaryPath) {
        const analysis = await this.analyze(binaryPath);
        return analysis.protocols.includes('HTX') ||
            analysis.endpoints.some(e => e.includes('/betanet/htx'));
    }
    async supportsQUIC(binaryPath) {
        const analysis = await this.analyze(binaryPath);
        return analysis.protocols.includes('QUIC') &&
            analysis.ports.includes(443);
    }
    async hasTLS13WithECH(binaryPath) {
        const analysis = await this.analyze(binaryPath);
        return analysis.tlsConfig.hasTLS13 && analysis.tlsConfig.hasECH;
    }
}
exports.NetworkAnalyzer = NetworkAnalyzer;
//# sourceMappingURL=network-analyzer.js.map