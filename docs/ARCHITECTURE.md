# Architecture and threat model

## Roles

- **Provider**: owns an SEV-SNP-capable server with an H100 in CC mode and runs
  `ccp serve` inside the confidential VM. The provider's *operator* (and the
  cloud/hypervisor beneath it) is untrusted.
- **Client**: verifies evidence, then sends a sealed prompt.
- **Vendors**: AMD and NVIDIA are trusted roots. Their keys sign the evidence.

## Request flow

```
Client                                         Provider (inside CVM)
  | GET /v1/attestation?nonce=N                      |
  |------------------------------------------------->|  generate evidence with
  |                                                  |  report_data = H(N, enclave_pk, models)
  |<-- bundle {cpu report + VCEK, gpu evidence,      |
  |            enclave_pk, models[]} ----------------|
  | verify (see below)                               |
  | POST /v1/sealed/chat[/stream]                    |
  |   box(client_sk -> enclave_pk, {prompt, ts})  -->|  decrypt, check freshness + replay,
  |<-- box(enclave_sk -> client_pk, reply chunks) ---|  forward to loopback engine
```

## What the client verifies

1. **CPU evidence** (`cc-attest::snp`): the SNP report's signature chains
   through the VCEK and AMD's ASK to AMD's ARK. The roots are compiled in and
   never taken from the server. Then: guest policy forbids debug and migration
   agents; VMPL is 0; the VCEK's certified TCB and chip id equal the report's
   (so a host on old firmware cannot claim a newer TCB); the VCEK is within its
   validity dates; the TCB meets the client's per-component minimum.
2. **Binding**: `report_data` equals `sha256(domain || nonce || enclave_pk || models_digest)`.
   This ties the evidence to *this* key, *this* nonce (no replay of old
   evidence) and *this exact model list*.
3. **Measurement**: the launch measurement is in the client's allowed set. The
   measurement covers firmware, kernel, initrd and `ccp`, so it is only
   meaningful if the image is reproducibly built and the hash is published.
4. **GPU evidence** (`cc-attest::gpu`): NVIDIA-signed tokens (ES384, keys from a
   JWKS the client pins), nonce derived from the same `report_data`, overall
   result true, secure boot on, debug disabled, measurements matching.
5. **Models**: every model the client requires appears with the pinned
   manifest digest.

Verification happens before the prompt is encrypted. On any failure nothing is
sent.

## Models are part of the attestation

A model's identity is a manifest digest: a hash over `(repo, immutable commit,
every file's path, size, sha256)`. `ccp serve` **re-hashes all weights at every
start** and attests the result, and the enclave refuses requests for other
model names. A client that pins `--model id=digest` therefore knows which
weights answered. Anyone can recompute the digest from the public repo at the
named commit.

## Sealed transport

NaCl box (X25519 + XSalsa20-Poly1305), the same primitive Darkbloom uses.

- **Freshness and replay**: requests carry `issued_at`; the enclave accepts a
  5-minute window and remembers (sender, nonce) pairs inside it.
- **Streaming**: each SSE event is one sealed `StreamChunk{seq, delta, done}`.
  The client requires contiguous `seq` and a final `done`, so a host cannot
  truncate, reorder or replay a reply unnoticed.
- **Engine**: forwarding is restricted to a loopback engine URL so plaintext
  stays inside the VM.

## Threats and limits

| Threat | Mitigation | Gap |
|---|---|---|
| Operator reads memory | SNP memory encryption; debug and migration forbidden | Hardware/firmware vulnerabilities in SEV-SNP. Keep a TCB floor. |
| Operator swaps the software | Launch measurement pinned | Needs reproducible image + published hash (not built yet) |
| Operator swaps model weights | Weights re-hashed at start; digest attested | Weights are on a host-controlled disk; integrity relies on the hash check inside the VM |
| Old evidence replayed | Fresh nonce bound in `report_data` | none known |
| Sealed request replayed | Timestamp window + replay cache | Replay *within* the cache after a provider restart (cache is in memory) |
| Stream truncated | Mandatory `done` chunk | none known |
| Fake GPU / GPU not confidential | NVIDIA token checks | Claim names unvalidated on real tokens; CC mode inferred, not read directly |
| Man in the middle | Prompt sealed to attested key | Metadata visible: timing, sizes, endpoint |
| Provider denial of service | none | By design out of scope |
| Per-session forward secrecy | none | The enclave key lives for the process; a leaked key exposes that run's recorded traffic |
| VCEK revocation | not checked | No CRL handling |
| One host holds `ccp` and the engine | Engine on loopback | A compromised engine sees plaintext; it is inside the measured image |

## Not implemented

Intel TDX; reproducible image tooling; multi-GPU CPU/GPU evidence binding
beyond a shared nonce; per-session enclave keys; certificate revocation.
