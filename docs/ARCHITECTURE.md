# Architecture

## Flow
1. Client sends a fresh random nonce to `GET /v1/attestation`.
2. The enclave returns CPU evidence (+ GPU evidence) whose 64-byte `report_data`
   is `sha256("dist-cc-v1/report-data" || len(nonce) || nonce || enclave_pubkey)`
   zero-padded. This binds the evidence to this key and defeats replay.
3. The client verifies: evidence signature chain, binding, launch measurement in
   the allowed set, platform TCB >= minimum, GPU in CC mode.
4. Only then does it seal the prompt (NaCl box, client ephemeral key -> enclave
   key). The enclave seals the reply back. Nothing is sent if verification fails.

## What is measured
A binary cannot attest itself. The launch measurement covers the whole VM image
(firmware, kernel, initrd, the server binary). Users must be able to rebuild the
image reproducibly and obtain the same measurement; publish that hash.

## Not protected
Traffic metadata, host denial of service, hardware/firmware vulnerabilities
(keep a minimum-TCB check), bugs in this binary (it handles plaintext).

## Roadmap
1. [x] Protocol, mock attestation, verifier policy, e2e tests
2. [x] SEV-SNP verifier (`cc-attest/src/snp.rs`): pinned ARK/ASK (Milan/Genoa/Turin) ->
   VCEK -> report signature; rejects debug-enabled guests; checks VCEK TCB and chip id
   equal the report's. Tested against a real Milan report. **Still to do:** cert
   validity dates / CRL, VMPL check, and a check against real Genoa/Turin evidence.
3. [ ] TDX verifier (DCAP quote)
4. [ ] NVIDIA GPU verifier (NRAS or local verifier); bind GPU+CPU evidence
5. [ ] Real `Attester`: SNP via `/dev/sev-guest` + VCEK fetch from AMD KDS (first), then NVIDIA SDK; TDX later
6. [ ] Backend forwarding to a local engine (e.g. vLLM) over loopback; streaming
7. [ ] Reproducible CVM image + published measurement
8. [ ] Forward secrecy (per-request enclave key) and replay protection on `/v1/sealed/chat`

## Test-hardware note
Steps 3-5 need a confidential VM. Confirm the host exposes SEV-SNP/TDX and lets
you put the H100 in CC mode *before* spending GPU hours; marketplace container
hosts (including, possibly, RunPod) generally do not. Develop and unit-test
everything above against recorded evidence first.
