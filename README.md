# dist-cc-cli

Confidential-compute inference for NVIDIA H100 servers. A single enclave server
runs inside a confidential VM (AMD SEV-SNP or Intel TDX) with the GPU in CC mode;
a client CLI verifies the attestation, then sends an encrypted prompt.

**Status: early.** The client-side **AMD SEV-SNP verifier** is implemented and
tested against a real Milan report. The enclave side cannot yet *produce* real
evidence, the **NVIDIA GPU verifier is not implemented**, and TDX is not
supported (fails closed). The `mock` backend is INSECURE (public trust root); it
exists so the protocol runs without hardware. Until the GPU verifier exists,
only use `--no-gpu` with SNP evidence, which does not prove GPU confidentiality.

## Layout
| Crate | Role |
|---|---|
| `cc-proto` | Wire types, NaCl-box sealing, report-data binding |
| `cc-attest` | `Attester` (enclave side), `verify_bundle` + `Policy` (client side), mock backend |
| `cc-server` | In-enclave HTTP server: `GET /v1/attestation?nonce=`, `POST /v1/sealed/chat` |
| `cc-client` | CLI + library: `attest`, `chat` |

## Try it (no GPU)
```bash
cargo test --workspace
cargo run -p cc-server -- --mock &
M=$(printf '07%.0s' $(seq 48))
cargo run -p cc-client -- attest --url http://127.0.0.1:8443 --allow-mock --measurement $M
cargo run -p cc-client -- chat   --url http://127.0.0.1:8443 --allow-mock --measurement $M "hello"
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the protocol, what is and
is not protected, and the roadmap.
