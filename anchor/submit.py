import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from web3 import Web3

from ingest.schema import ClaimSet
from prover.run_proof import prove_all

load_dotenv(Path(__file__).parent.parent / "config.env")

CONTRACTS_DIR = Path(__file__).parent.parent / "contracts"
EXPLORER      = "https://explorer.hyperliquid-testnet.xyz"
HYPE_USD      = 3_000   # rough price for gas cost estimate; not used for logic


def get_w3() -> Web3:
    w3 = Web3(Web3.HTTPProvider(os.getenv("HL_TESTNET_RPC", "https://rpc.hyperliquid-testnet.xyz/evm")))
    if not w3.is_connected():
        raise ConnectionError("Cannot connect to HyperEVM testnet")
    return w3


def load_contract(w3: Web3, name: str):
    abi_path = CONTRACTS_DIR / f"{name}.abi.json"
    address  = os.getenv("AUDIT_ANCHOR_ADDRESS")
    if not address:
        raise ValueError("AUDIT_ANCHOR_ADDRESS not set — run anchor/deploy.py first")
    return w3.eth.contract(
        address=Web3.to_checksum_address(address),
        abi=json.loads(abi_path.read_text()),
    )


def anchor_claim(claim: ClaimSet) -> dict:
    """Full pipeline: prove_all -> submit to AuditAnchor. Returns result dict."""
    # 1. Generate ZK proofs for all circuits
    proof_result = prove_all(claim)

    # 2. Concatenate non-empty proof bytes; use sentinel byte for all-fail case
    raw_hex   = "".join(r["proof"] for r in proof_result["circuits"] if r["proof"]) or "00"
    proof_bytes = bytes.fromhex(raw_hex)

    # 3. Public inputs: timestamp as bytes32
    public_inputs = [claim.timestamp.to_bytes(32, "big")]

    # 4. Build and send transaction
    w3      = get_w3()
    account = w3.eth.account.from_key(os.getenv("HL_PRIVATE_KEY"))
    contract = load_contract(w3, "AuditAnchor")

    event_id = Web3.keccak(text=claim.event_id)
    start    = time.time()

    tx = contract.functions.anchorProof(
        event_id,
        proof_bytes,
        public_inputs,
        proof_result["overall_passed"],
        claim.timestamp,
        claim.event_type,
        "mfa_check,hours_check,role_check",
    ).build_transaction({
        "from":     account.address,
        "nonce":    w3.eth.get_transaction_count(account.address),
        "gas":      500_000,
        "gasPrice": w3.eth.gas_price,
    })

    signed  = account.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    latency_ms = int((time.time() - start) * 1000)

    gas_cost_eth = receipt.gasUsed * w3.eth.gas_price / 1e18
    gas_cost_usd = gas_cost_eth * HYPE_USD
    tx_hex       = tx_hash.hex()

    return {
        "event_id":      claim.event_id,
        "event_type":    claim.event_type,
        "overall_passed": proof_result["overall_passed"],
        "tx_hash":       tx_hex,
        "block":         receipt.blockNumber,
        "gas_used":      receipt.gasUsed,
        "gas_cost_usd":  round(gas_cost_usd, 6),
        "latency_ms":    latency_ms,
        "explorer_url":  f"{EXPLORER}/tx/{tx_hex}",
        "proof_result":  proof_result,
    }


if __name__ == "__main__":
    from ingest.normalise import normalise_file

    mock_path = str(Path(__file__).parent.parent / "ingest" / "mock_events.json")
    claims    = normalise_file(mock_path)

    targets = {
        "pass":  claims[0],   # event 1 — ConsoleLogin FIDO2 — PASS
        "fail":  claims[4],   # event 5 — ConsoleLogin no MFA — FAIL
    }

    for label, claim in targets.items():
        print(f"\n{'='*60}")
        print(f"Anchoring: {claim.event_type} | {claim.actor_email} | expected={label.upper()}")
        result = anchor_claim(claim)
        print(f"  Passed      : {result['overall_passed']}")
        print(f"  TX          : {result['tx_hash']}")
        print(f"  Block       : {result['block']}")
        print(f"  Gas used    : {result['gas_used']}")
        print(f"  Gas cost    : ${result['gas_cost_usd']}")
        print(f"  Latency     : {result['latency_ms']}ms")
        print(f"  Explorer    : {result['explorer_url']}")
