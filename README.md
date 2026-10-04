# dist-cc-cli

Confidential-compute inference on NVIDIA H100 servers, with client-side
verification. A provider runs one binary (`ccp`) inside an AMD SEV-SNP
confidential VM with the GPU in confidential-compute mode. A client verifies
the machine's attestation, then sends an encrypted prompt that only the
attested software can read.

## Status

Early. Read this before relying on it.

| Piece | State |
|---|---|
| Protocol, sealing, replay protection, sealed streaming | Done, tested |
| SEV-SNP verification (client) | Done; tested against one real **Milan** report |
| SEV-SNP evidence production (`/dev/sev-guest`, VCEK from AMD KDS) | Written; **never run on real hardware** |
| NVIDIA GPU verification | Written against NVIDIA's documented token format; **tested only with locally generated tokens** |
| Model download, hash verification, manifest digests, provider CLI | Done, tested against a mock Hugging Face Hub |
| Intel TDX | Not supported (fails closed) |
| Reproducible VM image + published measurement | Not started |
| Hardware validation (H100 + SNP) | Not done. See [docs/TESTING.md](docs/TESTING.md) |

The `--mock` attestation backend is **insecure** (its trust root is a public
constant). It exists so everything runs without hardware.

## What it protects, and what it does not

Protects prompts and replies from the machine's owner and from the network,
**if** the VM image is the one you audited and the hardware is genuine and up
to date. It does not hide traffic metadata (timing, sizes), cannot prevent a
host from denying service, and is only as strong as AMD's and NVIDIA's
hardware. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crates

| Crate | Role |
|---|---|
| `cc-proto` | Wire types, NaCl-box sealing, the report-data binding |
| `cc-attest` | Evidence verification (SNP, NVIDIA, mock) and `Policy` |
| `cc-hw` | In-VM evidence production: SNP report, AMD KDS client, GPU command collector |
| `cc-models` | Catalog, Hugging Face download, hash verification, local store |
| `cc-server` | The attested HTTP API: attestation, sealed chat, sealed streaming |
| `cc-provider` | `ccp`, the provider admin CLI |
| `cc-client` | `cc-client` CLI and library for consumers |

## Quick look (no hardware)

```bash
cargo test --workspace                       # ~90 tests, no GPU needed
cargo build --release -p cc-provider -p cc-client

CCP=./target/release/ccp
$CCP init
$CCP config set listen 127.0.0.1:8443        # default is 0.0.0.0; keep dev mode local
$CCP models available
$CCP models pull qwen2.5-0.5b-instruct       # ~1 GB real download from Hugging Face
$CCP models use qwen2.5-0.5b-instruct
$CCP serve --mock --echo &                   # INSECURE dev mode, echo backend

M=$(printf '07%.0s' $(seq 48))               # the mock measurement
./target/release/cc-client chat --url http://127.0.0.1:8443 \
  --allow-mock --measurement $M --model-name qwen2.5-0.5b-instruct "hello"
```

## Documentation

- [Provider guide](docs/PROVIDER.md): set up a confidential VM, choose models, serve
- [Client guide](docs/CLIENT.md): what verification proves, flags, pinning
- [Architecture and threat model](docs/ARCHITECTURE.md)
- [Hardware test runbook](docs/TESTING.md): what to validate in the H100 time

## License

Apache-2.0. See [LICENSE](LICENSE).
