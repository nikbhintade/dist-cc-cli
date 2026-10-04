# Hardware test runbook

Most of this repository is tested without hardware. These items are **not**,
and each can fail in ways fakes cannot show. Do them in this order; the first
two are cheap and decide whether the rest is possible.

Record real outputs as test fixtures (see the end) so they become regression
tests.

## 0. Before spending any GPU hours

On the target machine, **before** anything else:

```bash
ls -l /dev/sev-guest              # must exist
dmesg | grep -i -E 'sev|snp'      # should mention SEV-SNP active
nvidia-smi                        # GPUs visible
nvidia-smi conf-compute -f        # expect "CC status: ON" (flag may differ by driver)
```

If `/dev/sev-guest` is missing you are in a plain container or non-SNP VM and
**cannot** run the real path there. Marketplace-style container hosts
(including, possibly, RunPod) commonly are. Ask the provider whether they
expose SEV-SNP guests with GPU passthrough in CC mode *before* planning the
test around them.

## 1. CPU path (needs only an SNP guest; no GPU needed)

```bash
cargo build --release -p cc-provider -p cc-client
ccp doctor
ccp measurement                   # does the ioctl work? is debug off?
ccp serve --echo                  # real SNP evidence, echo backend, no GPU cmd
cc-client attest --url http://127.0.0.1:8443 --no-gpu \
  --measurement <value from ccp measurement>
```

Check:
- [ ] `ccp measurement` succeeds and reports `debug_allowed: false`.
- [ ] VCEK fetch works (KDS URL format, product detection for this CPU).
- [ ] `attest` verifies. If it fails, the message names the stage.
- [ ] Genoa/Turin hosts: chip-id handling and TCB check are only tested on
      Milan fixtures. Failure here is a likely bug, report it with the report.
- [ ] Save the raw report and VCEK (see fixtures).

## 2. GPU path (needs the H100 in CC mode)

1. Write your `gpu_attest_cmd` wrapper around NVIDIA's attestation tooling. It
   must print the NRAS document (see PROVIDER.md).
2. Run it by hand with a random nonce; inspect the tokens.
3. **Validate the claim names** against reality. `cc-attest/src/gpu.rs` assumes:
   `x-nvidia-overall-att-result`, `eat_nonce`, and per-GPU `secboot`, `dbgstat`
   (`"disabled"`), `measres` (`"success"`). If your tokens differ, the verifier
   will reject valid evidence (safe) or, worse, if a claim is absent it may not
   be checked as intended. Fix the constants and add a test from the real token.
4. **Prove CC mode is enforced.** Switch the GPU out of CC mode (or use a
   non-CC GPU) and confirm verification **fails**. The verifier infers "CC on"
   from a passing, non-debug attestation; if a non-CC GPU still passes, add an
   explicit check on the claim that reports it.
5. Fetch NVIDIA's JWKS, save it, and verify with `--nvidia-jwks <file>`.

## 3. End to end

```bash
ccp models pull qwen2.5-0.5b-instruct --revision <sha>
ccp models use qwen2.5-0.5b-instruct
ccp config set engine_cmd "vllm serve {model_path} --served-model-name {model_id} --host 127.0.0.1 --port {port}"
ccp config set gpu_attest_cmd "<your wrapper> {nonce}"
ccp serve
cc-client chat --url ... --measurement ... \
  --model qwen2.5-0.5b-instruct=<digest from ccp> \
  --nvidia-jwks file.json --stream "hello"
```

Check: [ ] streaming works through vLLM, [ ] attestation latency (GPU evidence
is slow; the server caps concurrent quotes at 2), [ ] throughput with CC mode
on, [ ] weights hashing time for your model size at `ccp serve` start.

## 4. Negative tests on real hardware

- [ ] Client with a wrong `--measurement` refuses.
- [ ] Client with a wrong `--model` digest refuses.
- [ ] Tamper a weight file and restart: `ccp serve` refuses.
- [ ] Re-send a captured sealed request: server returns 409.
- [ ] Kill the engine mid-stream: client reports truncation.

## Recording fixtures

Save real evidence under `crates/cc-attest/testdata/` (SNP report hex, VCEK
DER, NRAS document, JWKS) and add tests that verify them with a fixed `now`.
Scrub nothing that is a signature; do not commit anything that identifies a
tenant beyond the chip id, which is in every SNP report.

## Budgeting the limited hours

Do steps 0 and 1 on the cheapest SNP instance available and only bring up the
GPU instance for steps 2-4, with the wrapper script and model already staged.
Pre-download weights to persistent storage.
