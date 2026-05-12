import logging
from pathlib import Path
from ingest.normalise import normalise_file
from prover.run_proof import prove_all

logging.basicConfig(level=logging.WARNING)


def run_benchmark():
    mock_path = str(Path(__file__).parent.parent / "ingest" / "mock_events.json")
    claims = normalise_file(mock_path)

    print(f"\n{'Event Type':<28} {'Actor':<28} {'MFA':>4} {'Hours':>6} {'Role':>5} {'Pass':>5} {'ms':>7}")
    print("-" * 85)

    for claim in claims:
        result = prove_all(claim)
        c = {r["circuit"]: r for r in result["circuits"]}
        mfa  = "+" if c["mfa_check"]["passed"]   else "X"
        hrs  = "+" if c["hours_check"]["passed"]  else "X"
        rol  = "+" if c["role_check"]["passed"]   else "X"
        status = "PASS" if result["overall_passed"] else "FAIL"
        actor = claim.actor_email[:26]
        print(
            f"{claim.event_type:<28} {actor:<28} {mfa:>4} {hrs:>6} {rol:>5} "
            f"{status:>5} {result['total_latency_ms']:>6}ms"
        )


if __name__ == "__main__":
    run_benchmark()
