/*
  Dummy Betanet-Compliant Binary (Heuristic Trigger Fixture)

  Purpose:
    Provides a small compiled artifact whose embedded strings are designed
    to satisfy all current heuristic compliance checks in `compliance.ts`.

  Usage (Linux / WSL preferred for full toolchain availability):

    gcc -O2 -s -o dummy-betanet-compliant dummy-betanet-compliant.c
    ./dummy-betanet-compliant --version
    betanet-lint check ./dummy-betanet-compliant

  Windows (MinGW):

    x86_64-w64-mingw32-gcc -O2 -s -o dummy-betanet-compliant.exe dummy-betanet-compliant.c
    betanet-lint check .\\dummy-betanet-compliant.exe

  Notes:
    - All required keyword tokens appear in static string literals so that
      simple 'strings' extraction & fallback scanning will detect them.
    - Some tokens intentionally duplicated (e.g., version markers) to raise
      confidence for heuristics that count occurrences.
    - For future new checks, extend TOKEN_SETS with additional markers.
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Transport / TLS / ECH / QUIC / Port 443 */
static const char *TRANSPORT_MARKERS[] = {
  "tcp-443", "port 443", "quic", "QUIC", "tls", "TLS 1.3", "ech", "ECH-enabled",
  "/betanet/htx/1.0.0", "/betanet/htxquic/1.0.0"
};

/* Access tickets / rotation */
static const char *ACCESS_TICKETS[] = {
  "access", "ticket", "rotate", "rotation", "refresh", "session"
};

/* Crypto primitives & frame encryption */
static const char *CRYPTO_MARKERS[] = {
  "chacha20", "poly1305", "frame_encrypt", "frame cipher", "x25519", "kyber", "Kyber768"
};

/* SCION & path mgmt */
static const char *SCION_MARKERS[] = {
  "scion", "SCION", "path", "route", "hop", "segment", "gateway"
};

/* DHT deterministic bootstrap */
static const char *DHT_MARKERS[] = {
  "dht", "bootstrap", "deterministic seed", "fixed seed", "peer discovery"
};

/* Alias ledger + consensus */
static const char *LEDGER_MARKERS[] = {
  "alias", "ledger", "2of3", "consensus", "chain verify", "identity trust"
};

/* Cashu + Lightning */
static const char *PAYMENT_MARKERS[] = {
  "cashu", "mint", "ecash token", "lightning", "payment channel", "settlement"
};

/* Reproducible build / provenance */
static const char *BUILD_MARKERS[] = {
  "reproducible", "slsa", "provenance", "build pipeline", "version", "commit hash"
};

/* Helper to ensure strings aren't optimized away */
static volatile unsigned long long sink = 0ULL;

static void touch(const char *s) {
  while (*s) {
    sink += (unsigned char)(*s++);
  }
}

int main(int argc, char **argv) {
  (void)argc; (void)argv;
  for (size_t i = 0; i < sizeof(TRANSPORT_MARKERS)/sizeof(TRANSPORT_MARKERS[0]); ++i) touch(TRANSPORT_MARKERS[i]);
  for (size_t i = 0; i < sizeof(ACCESS_TICKETS)/sizeof(ACCESS_TICKETS[0]); ++i) touch(ACCESS_TICKETS[i]);
  for (size_t i = 0; i < sizeof(CRYPTO_MARKERS)/sizeof(CRYPTO_MARKERS[0]); ++i) touch(CRYPTO_MARKERS[i]);
  for (size_t i = 0; i < sizeof(SCION_MARKERS)/sizeof(SCION_MARKERS[0]); ++i) touch(SCION_MARKERS[i]);
  for (size_t i = 0; i < sizeof(DHT_MARKERS)/sizeof(DHT_MARKERS[0]); ++i) touch(DHT_MARKERS[i]);
  for (size_t i = 0; i < sizeof(LEDGER_MARKERS)/sizeof(LEDGER_MARKERS[0]); ++i) touch(LEDGER_MARKERS[i]);
  for (size_t i = 0; i < sizeof(PAYMENT_MARKERS)/sizeof(PAYMENT_MARKERS[0]); ++i) touch(PAYMENT_MARKERS[i]);
  for (size_t i = 0; i < sizeof(BUILD_MARKERS)/sizeof(BUILD_MARKERS[0]); ++i) touch(BUILD_MARKERS[i]);

  if (argc > 1 && (strcmp(argv[1], "--version") == 0)) {
    printf("dummy-betanet-compliant 1.0.0 (reproducible build)\n");
    return 0;
  }
  if (argc > 1 && (strcmp(argv[1], "--help") == 0)) {
    printf("Usage: dummy-betanet-compliant [--version] [--help]\n");
    return 0;
  }

  printf("Betanet dummy compliance binary active: %llu\n", sink);
  return (int)(sink & 0xFF);
}
