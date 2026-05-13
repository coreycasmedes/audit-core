# AGENTS.md

Context for coding agents working on audit-core. Read this before touching any file.

## Repo layout (what each file actually does)

```
ingest/
  schema.py       ClaimSet Pydantic model + to_proof_inputs(). Single source of truth
                  for the data shape that flows through the entire pipeline.
  normalise.py    Raw CloudTrail dict -> ClaimSet. All field extraction logic lives here.
                  Never raises — logs warnings and uses safe defaults.
  cloudtrail.py   AWS CloudTrail poller + mock fallback. DEMO_MODE=mock skips AWS.
  mock_events.json  10 hand-crafted CloudTrail events. Edit here to add test scenarios.
  __main__.py     Spike 1 kill condition runner: python -m ingest

circuits/
  mfa_check/      Proves MFA used + not plain password. Input: mfa_flag (bool), auth_method (u8)
  hours_check/    Proves timestamp in [06:00, 22:00) UTC. Input: timestamp (u64), hour bounds (pub u8)
  role_check/     Proves actor ARN hash in approved set. Input: actor_hash (Field), allowed_hashes (pub [Field;8])
  Each circuit:   Nargo.toml + src/main.nr. assert() enforces the constraint so nargo execute
                  exits non-zero on violation — no proof generated means check failed.

prover/
  run_proof.py    Orchestrates the full proving pipeline per claim. Key exports:
                    field_hash(s) -> _FieldInt   sha256 mod BN254 prime, serialises as hex in TOML
                    prove_all(claim) -> dict      runs all 3 circuits, returns combined result
  benchmark.py    Runs prove_all on all 10 mock events, prints table. Entry point for Spike 2.
```

## Environment setup

```bash
# Python
uv sync                          # installs all deps into .venv

# Noir toolchain (nargo 1.x)
curl -L https://raw.githubusercontent.com/noir-lang/noirup/main/install | bash
noirup                           # installs latest stable nargo (~1.0.0-beta.x)

# Barretenberg proving backend
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/master/barretenberg/bbup/install | bash
bbup                             # auto-matches bb version to installed nargo

# Both binaries must be on PATH
export PATH="$HOME/.nargo/bin:$HOME/.bb:$PATH"
```

## Run commands

```bash
# Spike 1 — ingest
uv run python -m ingest

# Spike 2 — ZK benchmark (30 proofs, ~30-60s total)
uv run python -m prover.benchmark

# Compile a single circuit (run from circuit directory)
cd circuits/mfa_check && nargo compile

# Generate VK for a circuit (required before first prove)
bb write_vk -b target/mfa_check.json -o target/vk

# Manual prove cycle (run from circuit directory)
nargo execute
bb prove -b target/mfa_check.json -w target/mfa_check.gz \
         -o proofs/mfa_check.proof -k target/vk/vk

# Verify a proof
bb verify -p proofs/mfa_check.proof/proof \
          -k target/vk/vk \
          -i proofs/mfa_check.proof/public_inputs
```

## Proving pipeline (nargo 1.x — important)

`nargo prove` was removed in nargo 1.x. The pipeline is now split:

```
nargo compile   ->  target/<name>.json       ACIR bytecode  (cache: skip if exists)
bb write_vk     ->  target/vk/vk             verification key (cache: skip if exists)
nargo execute   ->  target/<name>.gz         witness from Prover.toml
                    exits 1 if assert fires  -> passed = False, no proof
bb prove        ->  proofs/<name>.proof/proof
                    proofs/<name>.proof/public_inputs
```

`prover/run_proof.py:_ensure_artifacts()` handles the caching. Compile and VK generation
happen once per circuit and are skipped on subsequent runs.

## Prover.toml formatting rules

`write_prover_toml()` in `prover/run_proof.py` handles serialisation. Rules:
- `bool` inputs → `true` / `false`
- `u8`, `u64` inputs → plain integer
- `Field` inputs → hex string `"0x..."` (BN254 prime ~2^254 overflows TOML int64)
- Arrays → `[val1, val2, ...]` with each element formatted by its type

Field values must be wrapped in `_FieldInt(int)` — this subclass is the marker that
triggers hex serialisation. `field_hash()` returns `_FieldInt`. Zero-padding for
`allowed_hashes` must also use `_FieldInt(0)`, not plain `0`.

## Noir 1.x syntax constraints

- `u1` is removed — use `bool` instead
- No non-ASCII characters anywhere in `.nr` files (em dashes, smart quotes, etc. cause parse errors)
- `assert(condition)` with no message is the constraint enforcement pattern used here

## auth_method encoding

Consistent across Python (`ingest/schema.py`) and Noir (`circuits/mfa_check/src/main.nr`):

| Value | Meaning | mfa_check result |
|-------|---------|-----------------|
| 0 | UNKNOWN | FAIL |
| 1 | FIDO2 | PASS |
| 2 | TOTP | PASS |
| 3 | PASSWORD | FAIL |

## Approved actors (role_check)

Hardcoded in `prover/run_proof.py:build_inputs()` for the POC. In production this comes
from customer policy config. Current approved set:
- `arn:aws:iam::123456789012:user/jane.chen@acme.com`
- `arn:aws:iam::123456789012:user/mark.patel@acme.com`
- `arn:aws:iam::123456789012:user/sara.johnson@acme.com`
- `arn:aws:iam::123456789012:user/admin@acme.com`

Padded to 8 slots with `_FieldInt(0)`.

## Mock event scenarios

| Index | Scenario | Expected failure |
|-------|----------|-----------------|
| 0 | ConsoleLogin, FIDO2, 10:15 UTC, us-east-1, jane.chen | none — PASS |
| 1 | ConsoleLogin, TOTP, 14:31 UTC, us-east-1, mark.patel | none — PASS |
| 2 | AssumeRole, TOTP, 09:22 UTC, us-east-1, sara.johnson | none — PASS |
| 3 | AssumeRole, TOTP, **02:31 UTC**, us-east-1, jane.chen | hours_check |
| 4 | ConsoleLogin, **no MFA**, 11:05 UTC, us-east-1, mark.patel | mfa_check |
| 5 | AssumeRole, TOTP, 15:08 UTC, **ap-southeast-1**, contractor | role_check |
| 6 | AttachRolePolicy, TOTP, 10:45 UTC, us-east-1, sara.johnson | none — PASS |
| 7 | StopLogging, TOTP, 13:15 UTC, us-east-1, jane.chen | none — PASS (HIGH SEVERITY) |
| 8 | CreateAccessKey, TOTP, 11:33 UTC, us-east-1, mark.patel | none — PASS |
| 9 | DeleteUser, TOTP, 16:22 UTC, us-east-1, admin | none — PASS |

## Adding a new circuit

1. Create `circuits/<name>/Nargo.toml` and `circuits/<name>/src/main.nr`
2. Compile: `cd circuits/<name> && nargo compile`
3. Generate VK: `bb write_vk -b target/<name>.json -o target/vk`
4. Add a `build_inputs(claim, "<name>")` branch in `prover/run_proof.py`
5. Add `"<name>"` to the `circuits` list in `prove_all()`
6. Add a mock Prover.toml test case to verify pass and fail paths

## Secrets

Never commit `config.env`. It is in `.gitignore`. Use `config.env.example` as the template.
The `cloudtrail.py` fetch function falls back to mock events automatically when
`AWS_ACCESS_KEY_ID` is unset or `DEMO_MODE=mock`.

## Spike status

- Spike 1 (ingest): complete
- Spike 2 (ZK proof): complete
- Spike 3 (HyperEVM anchor): not started — needs `anchor/deploy.py`, `anchor/submit.py`, `anchor/receipt.py`, `contracts/AuditAnchor.sol`, `contracts/Verifier.sol`
