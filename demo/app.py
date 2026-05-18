"""Demo FastAPI server — SSE pipeline + mock anchor. No real blockchain needed."""
import asyncio
import hashlib
import json
import logging
import random
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, StreamingResponse

from ingest.normalise import normalise_file
from prover.run_proof import prove_all

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="audit-core demo")
_executor = ThreadPoolExecutor(max_workers=2)

MOCK_PATH = str(Path(__file__).parent.parent / "ingest" / "mock_events.json")
_claims = normalise_file(MOCK_PATH)

# Maps UI scenario label → index in mock_events.json
SCENARIO_INDEX = {
    "pass": 0,       # ConsoleLogin FIDO2 — PASS all three
    "fail_mfa": 4,   # ConsoleLogin no-MFA — FAIL mfa_check
    "fail_hours": 3, # AssumeRole 02:31 UTC — FAIL hours_check
    "fail_role": 5,  # AssumeRole contractor — FAIL role_check
}

_records: list[dict] = []  # in-memory store, newest-first


def _sse(event: str, data: dict) -> str:
    return f"event: {event}\ndata: {json.dumps(data)}\n\n"


def _mock_anchor(proof_result: dict) -> dict:
    seed = proof_result["event_id"].encode()
    fake_tx = "0x" + hashlib.sha256(seed + b"tx").hexdigest()
    fake_block = 4_200_000 + random.randint(0, 999)
    gas_used = random.randint(85_000, 120_000)
    return {
        "tx_hash": fake_tx,
        "block": fake_block,
        "gas_used": gas_used,
        "gas_cost_usd": round(gas_used * 1e-9 * 3000, 6),
        "explorer_url": f"https://explorer.hyperliquid-testnet.xyz/tx/{fake_tx}",
    }


async def _pipeline(scenario: str):
    idx = SCENARIO_INDEX.get(scenario, 0)
    if idx >= len(_claims):
        yield _sse("error", {"message": "invalid scenario"})
        return

    claim = _claims[idx]
    t0 = time.time()

    yield _sse("start", {
        "scenario": scenario,
        "event_id": claim.event_id,
        "event_type": claim.event_type,
        "actor": claim.actor_email,
        "auth_method": claim.auth_method,
        "timestamp": claim.timestamp,
        "source_region": claim.source_region,
    })

    ingest_ms = int((time.time() - t0) * 1000)
    yield _sse("normalised", {
        "ingest_ms": ingest_ms,
        "mfa_used": claim.mfa_used,
        "is_root": claim.is_root,
        "is_human": claim.is_human,
        "session_age_seconds": claim.session_age_seconds,
    })

    # prove_all is blocking — run in thread pool
    loop = asyncio.get_event_loop()
    t_prove = time.time()
    proof_result = await loop.run_in_executor(_executor, prove_all, claim)
    prove_ms = int((time.time() - t_prove) * 1000)

    yield _sse("proved", {
        "prove_ms": prove_ms,
        "overall_passed": proof_result["overall_passed"],
        "circuits": [
            {
                "circuit": r["circuit"],
                "passed": r["passed"],
                "latency_ms": r["latency_ms"],
                "proof_len": len(r["proof"]) // 2 if r["proof"] else 0,
            }
            for r in proof_result["circuits"]
        ],
    })

    t_anchor = time.time()
    anchor = _mock_anchor(proof_result)
    anchor_ms = int((time.time() - t_anchor) * 1000)

    record = {
        "event_id": claim.event_id,
        "event_type": claim.event_type,
        "actor": claim.actor_email,
        "auth_method": claim.auth_method,
        "timestamp": claim.timestamp,
        "overall_passed": proof_result["overall_passed"],
        "circuits": proof_result["circuits"],
        "tx_hash": anchor["tx_hash"],
        "block": anchor["block"],
        "gas_used": anchor["gas_used"],
        "gas_cost_usd": anchor["gas_cost_usd"],
        "explorer_url": anchor["explorer_url"],
        "total_ms": int((time.time() - t0) * 1000),
        "ingest_ms": ingest_ms,
        "prove_ms": prove_ms,
        "anchor_ms": anchor_ms,
        "anchored_at": int(time.time()),
    }
    _records.insert(0, record)
    if len(_records) > 200:
        _records.pop()

    yield _sse("anchored", {
        "anchor_ms": anchor_ms,
        "tx_hash": anchor["tx_hash"],
        "block": anchor["block"],
        "gas_used": anchor["gas_used"],
        "gas_cost_usd": anchor["gas_cost_usd"],
        "explorer_url": anchor["explorer_url"],
    })

    yield _sse("complete", {
        "total_ms": record["total_ms"],
        "overall_passed": proof_result["overall_passed"],
    })


@app.post("/demo/trigger")
async def trigger(body: dict):
    scenario = body.get("scenario", "pass")

    async def gen():
        async for chunk in _pipeline(scenario):
            yield chunk

    return StreamingResponse(gen(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.get("/records")
def get_records():
    return _records[:20]


@app.get("/health")
def health():
    return {"status": "ok", "mock_anchor": True, "claims_loaded": len(_claims)}


@app.get("/", response_class=HTMLResponse)
def index():
    return (Path(__file__).parent / "index.html").read_text()


@app.get("/auditor", response_class=HTMLResponse)
def auditor():
    return (Path(__file__).parent / "auditor.html").read_text()
