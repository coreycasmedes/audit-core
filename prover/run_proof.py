import subprocess, time, os, hashlib, shutil, logging
from pathlib import Path
from ingest.schema import ClaimSet

logger = logging.getLogger(__name__)

CIRCUITS_DIR = Path(__file__).parent.parent / "circuits"
BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617

NARGO = shutil.which("nargo") or os.path.expanduser("~/.nargo/bin/nargo")
BB = shutil.which("bb") or os.path.expanduser("~/.bb/bb")


class _FieldInt(int):
    """Noir Field-type integer — written as hex string in Prover.toml."""


def field_hash(s: str) -> _FieldInt:
    h = int(hashlib.sha256(s.encode()).hexdigest(), 16)
    return _FieldInt(h % BN254_PRIME)


def _toml_val(v) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, _FieldInt):
        return f'"0x{v:x}"'
    return str(v)


def write_prover_toml(circuit: str, inputs: dict) -> None:
    toml_path = CIRCUITS_DIR / circuit / "Prover.toml"
    lines = []
    for k, v in inputs.items():
        if isinstance(v, list):
            items = ", ".join(_toml_val(x) for x in v)
            lines.append(f"{k} = [{items}]")
        else:
            lines.append(f"{k} = {_toml_val(v)}")
    toml_path.write_text("\n".join(lines) + "\n")


def _ensure_artifacts(circuit: str) -> bool:
    """Compile and write VK if not already cached. Returns True on success."""
    circuit_dir = CIRCUITS_DIR / circuit
    acir_path = circuit_dir / "target" / f"{circuit}.json"
    vk_dir = circuit_dir / "target" / "vk"
    vk_path = vk_dir / "vk"

    if not acir_path.exists():
        r = subprocess.run([NARGO, "compile"], cwd=circuit_dir, capture_output=True, text=True)
        if r.returncode != 0:
            logger.error("nargo compile failed for %s: %s", circuit, r.stderr[:300])
            return False

    if not vk_path.exists():
        r = subprocess.run(
            [BB, "write_vk", "-b", str(acir_path), "-o", str(vk_dir)],
            cwd=circuit_dir, capture_output=True, text=True
        )
        if r.returncode != 0:
            logger.error("bb write_vk failed for %s: %s", circuit, r.stderr[:300])
            return False

    return True


def run_nargo(circuit: str) -> tuple[bool, str, int]:
    """
    nargo 1.x pipeline: compile/vk (cached) -> execute -> bb prove.
    Returns (success, proof_hex, latency_ms).
    execute fails fast with non-zero exit if assert fires -> passed=False.
    """
    circuit_dir = CIRCUITS_DIR / circuit
    acir_path = circuit_dir / "target" / f"{circuit}.json"
    witness_path = circuit_dir / "target" / f"{circuit}.gz"
    vk_path = circuit_dir / "target" / "vk" / "vk"
    proof_dir = circuit_dir / "proofs" / f"{circuit}.proof"
    (circuit_dir / "proofs").mkdir(exist_ok=True)

    start = time.time()

    if not _ensure_artifacts(circuit):
        return False, "", int((time.time() - start) * 1000)

    # Solve witness; assertion failure exits non-zero -> policy check failed
    r = subprocess.run([NARGO, "execute"], cwd=circuit_dir, capture_output=True, text=True)
    if r.returncode != 0:
        return False, "", int((time.time() - start) * 1000)

    r = subprocess.run(
        [BB, "prove",
         "-b", str(acir_path),
         "-w", str(witness_path),
         "-o", str(proof_dir),
         "-k", str(vk_path)],
        cwd=circuit_dir, capture_output=True, text=True
    )

    latency_ms = int((time.time() - start) * 1000)
    success = r.returncode == 0
    proof_hex = ""
    if success:
        proof_file = proof_dir / "proof"
        if proof_file.exists():
            proof_hex = proof_file.read_bytes().hex()

    return success, proof_hex, latency_ms


def build_inputs(claim: ClaimSet, circuit: str) -> dict:
    if circuit == "mfa_check":
        auth_enc = {"FIDO2": 1, "TOTP": 2, "PASSWORD": 3, "UNKNOWN": 0}
        return {
            "mfa_flag": claim.mfa_used,
            "auth_method": auth_enc[claim.auth_method],
        }
    if circuit == "hours_check":
        return {
            "timestamp": claim.timestamp,
            "allowed_start_hour": 6,
            "allowed_end_hour": 22,
        }
    if circuit == "role_check":
        approved = [
            "arn:aws:iam::123456789012:user/jane.chen@acme.com",
            "arn:aws:iam::123456789012:user/mark.patel@acme.com",
            "arn:aws:iam::123456789012:user/sara.johnson@acme.com",
            "arn:aws:iam::123456789012:user/admin@acme.com",
        ]
        hashes = [field_hash(a) for a in approved]
        hashes += [_FieldInt(0)] * (8 - len(hashes))
        return {
            "actor_hash": field_hash(claim.actor_arn),
            "allowed_hashes": hashes,
        }
    raise ValueError(f"Unknown circuit: {circuit}")


def generate_proof(claim: ClaimSet, circuit: str) -> dict:
    """Generate a ZK proof for a single claim + circuit combination."""
    inputs = build_inputs(claim, circuit)
    write_prover_toml(circuit, inputs)
    success, proof_hex, latency_ms = run_nargo(circuit)
    return {
        "event_id": claim.event_id,
        "circuit": circuit,
        "passed": success,
        "proof": proof_hex,
        "latency_ms": latency_ms,
        "actor_hash": int(field_hash(claim.actor_arn)),
        "timestamp": claim.timestamp,
    }


def prove_all(claim: ClaimSet) -> dict:
    """Run all three circuits for a claim. Returns combined result."""
    circuits = ["mfa_check", "hours_check", "role_check"]
    results = [generate_proof(claim, c) for c in circuits]
    overall_passed = all(r["passed"] for r in results)
    total_ms = sum(r["latency_ms"] for r in results)
    return {
        "event_id": claim.event_id,
        "event_type": claim.event_type,
        "actor": claim.actor_email,
        "timestamp": claim.timestamp,
        "overall_passed": overall_passed,
        "total_latency_ms": total_ms,
        "circuits": results,
    }
