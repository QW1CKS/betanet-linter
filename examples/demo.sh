#!/bin/bash

# Example script demonstrating Betanet Compliance Linter usage
# This script shows various ways to use the linter tool

set -e

echo "🚀 Betanet Compliance Linter - Example Usage"
echo "============================================"

# Create a dummy binary for demonstration
echo "Creating demonstration binary..."
cat > demo-betanet-app << 'EOF'
#!/bin/bash
# Dummy Betanet application for demonstration
echo "Betanet Application v1.0.0"
echo "Supporting HTX over TCP-443 and QUIC-443"
echo "TLS 1.3 with ECH enabled"
echo "ChaCha20-Poly1305 encryption active"
echo "Access tickets rotating every 300s"
echo "SCION paths: 3 active"
echo "DHT bootstrap: deterministic"
echo "Alias ledger: 2-of-3 consensus"
echo "Cashu vouchers accepted"
echo "Lightning settlement supported"
echo "SLSA 3 provenance published"
EOF

chmod +x demo-betanet-app

echo ""
echo "📋 Running compliance checks..."
echo "==============================="

# Example 1: Basic console output
echo "1. Basic console output:"
echo "-------------------------"
betanet-lint check ./demo-betanet-app

echo ""
echo "2. Table output format:"
echo "----------------------"
betanet-lint check ./demo-betanet-app --output table

echo ""
echo "3. JSON output format:"
echo "----------------------"
betanet-lint check ./demo-betanet-app --output json

echo ""
echo "4. Verbose output:"
echo "-----------------"
betanet-lint check ./demo-betanet-app --verbose

echo ""
echo "5. With SBOM generation:"
echo "----------------------"
betanet-lint check ./demo-betanet-app --sbom

echo ""
echo "6. GitHub Action format:"
echo "----------------------"
betanet-lint check ./demo-betanet-app --github-action

echo ""
echo "📦 SBOM Generation Examples"
echo "=========================="

# Example SBOM generation
echo "7. CycloneDX SBOM:"
echo "-----------------"
betanet-lint sbom ./demo-betanet-app --format cyclonedx
ls -la demo-betanet-app.cyclonedx.json

echo ""
echo "8. SPDX SBOM:"
echo "-------------"
betanet-lint sbom ./demo-betanet-app --format spdx
ls -la demo-betanet-app.spdx

echo ""
echo "🔍 Error Handling Examples"
echo "========================="

# Example with non-existent binary
echo "9. Non-existent binary:"
echo "----------------------"
if ! betanet-lint check ./non-existent-app 2>/dev/null; then
    echo "✅ Correctly handled non-existent binary"
fi

# Example with non-executable file
echo "10. Non-executable file:"
echo "------------------------"
echo "This is not executable" > non-executable.txt
if ! betanet-lint check ./non-executable.txt 2>/dev/null; then
    echo "✅ Correctly handled non-executable file"
fi

echo ""
echo "📊 Summary of Results"
echo "====================="

# Show generated files
echo "Generated files:"
ls -la demo-betanet-app* 2>/dev/null || echo "No files generated"

echo ""
echo "🧹 Cleanup"
echo "========="

# Clean up demonstration files
rm -f demo-betanet-app demo-betanet-app.cyclonedx.json demo-betanet-app.spdx non-executable.txt

echo "✅ Demo completed successfully!"
echo ""
echo "For more information, see the README.md file or run:"
echo "  betanet-lint --help"
echo "  betanet-lint check --help"
echo "  betanet-lint sbom --help"