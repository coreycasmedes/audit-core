# audit-core

ZK-powered compliance audit system. Proves AWS admin actions are policy-compliant using zero-knowledge proofs anchored to HyperEVM.

## What it does

Every watched AWS admin action — console logins, role assumptions, IAM changes, CloudTrail mutations — is normalised into a `ClaimSet`, run through three ZK circuits, and the proof is anchored on-chain. An external auditor can verify any record independently with no intermediary and no login.

The core property: a ZK proof proves a policy check **ran** on raw data without exposing the raw data. A missing proof in the sequence is itself a detection signal.

## Architecture

```
AWS CloudTrail
      |
      v
ingest/normalise.py      ClaimSet (structured claim, hashed raw event)
      |
      v
circuits/                Three Noir circuits (UltraHonk via Barretenberg)
  mfa_check/               MFA used + not plain password
  hours_check/             Action within 06:00–22:00 UTC
  role_check/              Actor hash in approved set
      |
      v
prover/run_proof.py      nargo execute -> bb prove -> proof bytes
      |
      v
anchor/                  HyperEVM testnet (chain ID 998)
  AuditAnchor.sol          Immutable on-chain record per event
  Verifier.sol             Proof format verification
      |
      v
demo/                    FastAPI + SSE pipeline + auditor view
```

## Spikes

| Spike | Kill condition | Status |
|-------|---------------|--------|
| 1 — Ingest | 10 mock events → valid `ClaimSet` in < 100ms each | done — 0.06ms/event |
| 2 — Prove | Valid proof in < 5s; violations fail the right circuit | done — 2.6s worst case |
| 3 — Anchor | Proof on HyperEVM testnet in < 10s, gas < $0.10 | pending |

## Quickstart

```bash
# Prerequisites
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash && noirup
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash && bbup

# Install Python deps
uv sync

# Configure
cp config.env.example config.env   # fill in AWS + HyperEVM keys

# Run ingest (mock events)
uv run python -m ingest

# Run ZK benchmark (all 10 events x 3 circuits)
uv run python -m prover.benchmark
```

## ZK circuit design

All three circuits use UltraHonk (Barretenberg) via nargo 1.x. Private inputs never leave the prover. Public inputs/outputs are anchored on-chain.

**mfa_check** — proves MFA was used and auth method is FIDO2 or TOTP (not plain password or unknown). Fails for event 5 (no MFA).

**hours_check** — proves the action timestamp falls within `allowed_start_hour`–`allowed_end_hour` UTC (default 06:00–22:00). Fails for event 4 (02:31 UTC). Hour bounds are public so the auditor sees what policy was enforced.

**role_check** — proves the actor's ARN hash is in a public set of approved actors (padded to 8 slots). ARN hash is private; the approved set is public. Fails for event 6 (unauthorised contractor).

## Proof pipeline (nargo 1.x)

`nargo prove` was removed in nargo 1.x. The current pipeline:

```
nargo compile          ->  target/<circuit>.json   (ACIR, cached)
bb write_vk            ->  target/vk/vk            (cached)
nargo execute          ->  target/<circuit>.gz      (witness; exits 1 if assert fires)
bb prove               ->  proofs/<circuit>.proof/proof + public_inputs
```

An assertion failure in `nargo execute` means the policy check failed — no proof is generated for that circuit.

## Mock events

Ten realistic CloudTrail events covering the key scenarios:

| # | Event | Actor | Expected |
|---|-------|-------|----------|
| 1 | ConsoleLogin | jane.chen (FIDO2) | PASS all |
| 2 | ConsoleLogin | mark.patel (TOTP) | PASS all |
| 3 | AssumeRole AdminRole | sara.johnson | PASS all |
| 4 | AssumeRole AdminRole | jane.chen @ 02:31 UTC | FAIL hours |
| 5 | ConsoleLogin | mark.patel (no MFA) | FAIL mfa |
| 6 | AssumeRole | contractor.ext (ap-southeast-1) | FAIL role |
| 7 | AttachRolePolicy | sara.johnson | PASS |
| 8 | StopLogging | jane.chen | PASS (high severity) |
| 9 | CreateAccessKey | mark.patel | PASS |
| 10 | DeleteUser | admin | PASS |

## Config

Copy `config.env.example` to `config.env`. Set `DEMO_MODE=mock` to use the bundled events without AWS credentials.

```
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=us-east-1
HL_TESTNET_RPC=https://rpc.hyperliquid-testnet.xyz/evm
HL_CHAIN_ID=998
HL_PRIVATE_KEY=
AUDIT_ANCHOR_ADDRESS=
DEMO_MODE=mock
```

## HyperEVM testnet

- RPC: `https://rpc.hyperliquid-testnet.xyz/evm`
- Chain ID: `998`
- Explorer: `https://explorer.hyperliquid-testnet.xyz`
- Faucet: `https://app.hyperliquid-testnet.xyz/drip`
