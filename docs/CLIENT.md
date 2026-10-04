# Client guide

`cc-client` fetches an attestation bundle, verifies it against **your**
policy, and only then encrypts a prompt to the attested key. Verification is
only as strong as the policy you give it; the defaults are deliberately strict
(they accept nothing).

## Commands

```bash
cc-client attest --url https://provider:8443 [policy flags]
cc-client chat   --url https://provider:8443 [policy flags] [--stream] [--model-name ID] "prompt"
```

## Policy flags

| Flag | Meaning |
|---|---|
| `--measurement HEX` (repeatable) | Allowed SEV-SNP launch measurement(s). **Required**; with none, everything is rejected. |
| `--model ID=DIGEST` (repeatable) | Require this model with this manifest digest. Use the provider's published pin or recompute it yourself. With exactly one pin, `chat` requests that model unless `--model-name` says otherwise. |
| `--min-tcb B,T,S,U` | Minimum firmware levels (bootloader, tee, snp, microcode). Default `0,0,0,0` accepts anything; set it from AMD's current security bulletins. |
| `--forbid-smt` | Reject guests that allow host SMT. |
| `--nvidia-jwks FILE\|nras` | NVIDIA token-signing keys. Prefer a **file you pinned**. `nras` fetches NVIDIA's keys over HTTPS and trusts that endpoint. |
| `--min-gpus N` | Minimum attested GPUs (default 1). |
| `--no-gpu` | Do not require GPU evidence. Then nothing proves the GPU is confidential. |
| `--allow-mock` | Accept the insecure mock backend. Development only. |

## What a successful `attest` means

All of: AMD-signed report with a valid VCEK chain; debug and migration agents
off; fresh nonce bound to this key and model list; your measurement; TCB above
your floor; NVIDIA-signed GPU evidence for this session in a non-debug state;
your pinned models. See [ARCHITECTURE.md](ARCHITECTURE.md#what-the-client-verifies).

It does **not** mean the provider's software is good, only that it is the
software whose measurement you allowed. Audit what you allow.

## Pinning a model yourself

The digest is a hash over the repo, the commit and every file's sha256, so you
can reproduce it: `ccp models pull <id> --repo owner/name --revision <sha>` on
any machine prints the same `client pin:` line.

## Library use

`cc_client::chat`, `cc_client::chat_stream` and `cc_client::attest` take a
`cc_attest::Policy`; construct it explicitly. Streaming errors if the reply is
truncated or altered, so check the result.
