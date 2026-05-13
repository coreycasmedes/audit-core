import os
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

from anchor.submit import get_w3, load_contract

load_dotenv(Path(__file__).parent.parent / "config.env")

EXPLORER = "https://explorer.hyperliquid-testnet.xyz"


def verify_on_chain(event_id_str: str) -> dict:
    """Read a Record from AuditAnchor by event_id string."""
    w3       = get_w3()
    contract = load_contract(w3, "AuditAnchor")
    event_id = Web3.keccak(text=event_id_str)
    r        = contract.functions.getRecord(event_id).call()
    # Struct order: proofHash, passed, timestamp, anchoredAt, blockNumber, eventType, circuitSet
    return {
        "event_id":     event_id_str,
        "proof_hash":   r[0].hex(),
        "passed":       r[1],
        "timestamp":    r[2],
        "anchored_at":  r[3],
        "block_number": r[4],
        "event_type":   r[5],
        "circuit_set":  r[6],
        "contract_url": f"{EXPLORER}/address/{os.getenv('AUDIT_ANCHOR_ADDRESS')}",
    }


def get_auditor_report(from_block: int = 0) -> list[dict]:
    """Fetch all ProofAnchored events and return formatted list for auditor view."""
    w3       = get_w3()
    contract = load_contract(w3, "AuditAnchor")
    logs     = contract.events.ProofAnchored.get_logs(fromBlock=from_block)
    report   = []
    for log in logs:
        args   = log["args"]
        tx_hex = log["transactionHash"].hex()
        report.append({
            "event_id":   args["eventId"].hex(),
            "proof_hash": args["proofHash"].hex(),
            "passed":     args["passed"],
            "timestamp":  args["timestamp"],
            "event_type": args["eventType"],
            "tx_hash":    tx_hex,
            "block":      log["blockNumber"],
            "explorer_url": f"{EXPLORER}/tx/{tx_hex}",
        })
    return report


if __name__ == "__main__":
    print("Fetching all anchored records...\n")
    report = get_auditor_report()
    if not report:
        print("No records anchored yet.")
    for rec in report:
        status = "PASS" if rec["passed"] else "FAIL"
        print(f"[{status}] {rec['event_type']:<24} tx={rec['tx_hash'][:16]}...  {rec['explorer_url']}")
    print(f"\nTotal: {len(report)}")
