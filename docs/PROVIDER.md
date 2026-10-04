# Provider guide

This guide covers running `ccp` as an attested provider. Commands that depend
on your cloud or hypervisor are described, not scripted: they vary by platform
and are outside this repository. Verify driver and tool flags against your
installed versions.

## Requirements

- AMD EPYC (Milan, Genoa or Turin) with SEV-SNP enabled in firmware, and a
  hypervisor that launches your workload as an **SNP guest**.
- NVIDIA H100/H200/B200 passed through to that guest, with the GPU in
  **confidential-compute mode**.
- A guest kernel with the `sev-guest` driver (so `/dev/sev-guest` exists).
- Outbound access to `kdsintf.amd.com` (VCEK certificates) and your model host.
- Disk for weights: hundreds of GiB for large models.

A plain container or ordinary VM does **not** qualify. `ccp doctor` tells you
which requirement is missing.

## Setup

```bash
ccp init                  # writes ~/.config/dist-cc/config.toml (or $CCP_CONFIG)
ccp doctor                # PASS/WARN/FAIL for each requirement
```

### Choose and download models

```bash
ccp models available      # catalog, install state, fit for this host's VRAM
ccp models choose         # interactive: pick, download, activate
# or explicitly:
ccp models pull qwen2.5-72b-instruct --revision <commit-sha>
ccp models pull my-model --repo owner/name --revision <commit-sha>
ccp models use qwen2.5-72b-instruct
```

- Downloads resume after interruption and are verified file by file: LFS files
  by sha256, small files by git blob id. A corrupt file is deleted, not kept.
- A repo-supplied path that escapes the model directory is refused.
- Gated models need a Hugging Face token in the environment variable named by
  `hf_token_env` (default `HF_TOKEN`). The token is never written to the config.
- **Pin a commit** (`--revision <sha>` or in your catalog). `main` is resolved
  to a commit at pull time, but a moving branch means a changing digest.
- Use your own catalog with `ccp config set catalog /path/catalog.json`:

  ```json
  {"models":[{"id":"my-model","repo":"owner/name","revision":"<sha>",
              "min_vram_gb":160,"include":["*.safetensors","*.json","*.model"]}]}
  ```

### Inference engine

Run an OpenAI-compatible engine on loopback, started with the **catalog id** as
its served model name so the attested name matches what it serves. `ccp` will
only talk to a loopback engine URL.

Either start it yourself, or let `ccp` manage one model:

```bash
ccp config set engine_cmd "vllm serve {model_path} --served-model-name {model_id} --host 127.0.0.1 --port {port}"
```

Disable the engine's request logging (flag names vary by version) so prompts
are not written to disk. A managed engine serves exactly one model; for several
models run your own engine(s).

### GPU evidence

`ccp` does not link NVIDIA's attestation SDK. Provide a command that prints
NVIDIA's evidence document to stdout:

```bash
ccp config set gpu_attest_cmd "/opt/dist-cc/gpu-attest {nonce}"
```

Contract: the literal argument `{nonce}` is replaced with a 64-hex-char nonce;
the command must exit 0 and print the NRAS evidence JSON
`[["JWT","<overall token>"],{"GPU-0":"<token>", ...}]` whose `eat_nonce` equals
that nonce. Build it from NVIDIA's attestation tooling for your driver. This
repo ships no such script, because the tooling's interface changes between
releases; see [TESTING.md](TESTING.md) for validating it.

Without `gpu_attest_cmd`, no GPU evidence is produced and clients that require
a GPU report will refuse you.

### Serve

```bash
ccp measurement           # the launch measurement clients should pin
ccp models digest <id>    # the --model pin for each model (re-hashes weights)
ccp serve                 # hashes weights, starts engine, serves attested API
ccp status --verify
```

`ccp serve` re-hashes every active model on each start (slow for large
models, deliberately) and refuses to start if anything differs from its
manifest or an unexpected file is present. It prints a `client pin:` line per
model.

Publish to clients: the launch measurement, the model pins, and the NVIDIA
trust keys they should use. Clients should be able to rebuild your VM image and
get the same measurement; until you publish a reproducible build, the
measurement proves little.

## Command reference

| Command | Purpose |
|---|---|
| `ccp init` | Write default config (never overwrites) |
| `ccp config show / path / set K V` | View or change config; invalid values are rejected and not saved |
| `ccp doctor` | Environment checks; exits non-zero on any FAIL |
| `ccp models available / list / choose` | Browse and pick |
| `ccp models pull / verify / digest / rm` | Manage files and integrity |
| `ccp models use / unuse` | Set which models are served |
| `ccp status [--verify]` | Active models, digests, client pins |
| `ccp measurement` | SNP launch measurement of this VM |
| `ccp serve [--mock] [--echo]` | Run the server (`--mock` is insecure) |

## Config keys

`models_dir`, `catalog`, `hf_token_env`, `hf_base_url`, `listen`, `engine_url`,
`engine_cmd`, `active_models`, `kds_cache_dir`, `gpu_attest_cmd`. `listen`
defaults to `0.0.0.0:8443`; put the server behind TLS termination *inside* the
VM or accept that metadata is visible on the network (prompts are sealed
regardless).

## Operational notes

- VCEK certificates are cached in `kds_cache_dir`; AMD's service rate-limits by
  address, so keep the cache on persistent storage.
- Attestation requests are capped at two concurrent quotes; extra callers get
  503 and should retry.
- The replay cache is in memory; it resets on restart (the 5-minute timestamp
  window still applies).
