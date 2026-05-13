from pathlib import Path

from ingest.normalise import normalise_file

if __name__ == "__main__":
    mock_path = str(Path(__file__).parent / "mock_events.json")
    claims = normalise_file(mock_path)
    for c in claims:
        print(f"\n{'='*60}")
        print(f"Event: {c.event_type} | Actor: {c.actor_email}")
        print(f"Time: {c.timestamp} | Region: {c.source_region}")
        print(f"MFA: {c.mfa_used} ({c.auth_method}) | Human: {c.is_human}")
        print(f"Hash: {c.raw_hash[:16]}...")
    print(f"\nTotal: {len(claims)} claims normalised")
