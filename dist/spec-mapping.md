### Automated Spec Mapping (Top 50 Normative Clauses)

Coverage: 25/41 (60.98%) mapped via heuristic associations.

| Line | Clause (truncated) | Checks | Status |
|------|----------------------|--------|--------|
| 3 | > **Normative document.** All requirements marked **MUST**,  |  | Unmapped |
| 34 | **PQ requirement.** From *2027-01-01*, the **inner** key agr | 1,12,22,32,13,19,10,38 | Mapped |
| 36 | **Algorithm agility.** Implementations **MUST** expose a reg | 15,16,34 | Mapped |
| 72 | * **Ver** MUST be `0x02`. |  | Unmapped |
| 73 | * **Type** MUST be `0x01` (single path) or `0x03` (path list |  | Unmapped |
| 74 | * Each AS-hop signature in every segment **MUST** verify bef | 9,35 | Mapped |
| 78 | Gateways bridging non-SCION segments **MUST** encapsulate SC | 4,33,23 | Mapped |
| 90 | * Gateways **MUST** verify `TS` within **±300 s**, reject du |  | Unmapped |
| 92 | * Gateways **MUST** close and re-establish the control strea | 13,19,10,38,4,33,23 | Mapped |
| 94 | **Public-Internet requirement.** The legacy on-wire transiti |  | Unmapped |
| 100 | * Probe with exponential back-off (min 1 s, max 60 s); **MUS |  | Unmapped |
| 108 | * Clients **MUST** mirror the front origin’s fingerprint cla | 1,12,22,32 | Mapped |
| 109 | * A **per-connection calibration pre-flight** to the same or |  | Unmapped |
| 110 | * **Tolerances:** ALPN **set and order MUST match exactly**. | 1,12,22,32 | Mapped |
| 111 | * **POP selection:** If the origin presents geo/POP variance |  | Unmapped |
| 112 | * ALPN selection **MUST** match the origin; fixed global dis | 1,12,22,32 | Mapped |
| 113 | * Session resumption **MUST** follow origin policy; **0-RTT  |  | Unmapped |
| 139 | 9. Servers **MUST** parse fields in order (`version, cliPub3 | 2,30,20,28,26,37 | Mapped |
| 145 | * Inner handshake **MUST** be Noise *XK* over the outer TLS  | 1,12,22,32,13,19,10,38 | Mapped |
| 146 | * From *2027-01-01*, initiators **MUST** use hybrid (X25519- | 13,19,10,38 | Mapped |
| 152 | * Rekeying (**MUST** meet all): | 13,19,10,38 | Mapped |
| 156 | * Ordering: Receivers **MUST** accept `KEY_UPDATE` out-of-or | 13,19,10,38 | Mapped |
| 174 | * H2 SETTINGS **MUST** mirror origin within tolerances learn |  | Unmapped |
| 175 | * PING cadence **MUST** be random in **\[10 s, 60 s]** with  | 20,28,26,37 | Mapped |
| 183 | * To defeat induced linkability, clients **MUST** launch **c | 25,18 | Mapped |
| 184 | * Cover connections **MUST NOT** exceed **2** retries per mi | 25,18 | Mapped |
| 204 | Clients **MUST** iterate methods **a → e** until **≥ 5** pee |  | Unmapped |
| 215 | * Responders **MUST** require proof-of-work (initial **≥ 22  | 6,36,24 | Mapped |
| 226 | * Each bootstrap responder **MUST** maintain sliding-window  | 6,36,24 | Mapped |
| 227 | * Rate-limits **MUST** apply per `/24` IPv4, `/56` IPv6, and | 6,36,24 | Mapped |
| 246 | `BeaconSet(epoch) = SHA256("bn-fallback" ‖ K0c ‖ uint64_be(e | 11,17,27,25,18 | Mapped |
| 288 | * `seq` **MUST** increase monotonically per `pk`. |  | Unmapped |
| 303 | Each `sig` is Ed25519 over `("bn-aa1" ‖ payloadHash ‖ epoch) |  | Unmapped |
| 322 | * Relays **MUST** accept vouchers only for known keysets; un | 8,14,29,31,36 | Mapped |
| 323 | * Per-keyset and per-peer rate-limits **MUST** apply. | 6,36,24 | Mapped |
| 328 | Vouchers **MUST NOT** leave encrypted streams. | 8,14,29,31,36 | Mapped |
| 346 | * **Per-AS cap:** the **sum** of `vote_weight_raw` across al |  | Unmapped |
| 347 | * **Per-Org cap:** nodes mapped to the same RPKI organisatio | 9,35 | Mapped |
| 361 | After threshold, activation waits **≥ 30 days**. If §10.3 fa |  | Unmapped |
| 389 | * Legacy on-wire transition headers **MUST NOT** be used on  |  | Unmapped |
| 390 | * 64-B vouchers **MAY** be issued only to legacy peers; 1.1  | 8,14,29,31,36 | Mapped |

> Full JSON: dist/spec-mapping.json
