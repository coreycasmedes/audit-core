import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .normalise import WATCHED_EVENTS, normalise

logger = logging.getLogger(__name__)


def get_mock_events() -> list[dict]:
    return json.loads((Path(__file__).parent / "mock_events.json").read_text())


def fetch_recent_events(hours: int = 1) -> list[dict]:
    if os.getenv("DEMO_MODE", "mock") == "mock" or not os.getenv("AWS_ACCESS_KEY_ID"):
        return get_mock_events()
    try:
        import boto3
        client = boto3.client("cloudtrail", region_name=os.getenv("AWS_REGION", "us-east-1"))
        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=hours)
        raw_events: list[dict] = []
        for event_name in WATCHED_EVENTS:
            paginator = client.get_paginator("lookup_events")
            for page in paginator.paginate(
                LookupAttributes=[{"AttributeKey": "EventName", "AttributeValue": event_name}],
                StartTime=start,
                EndTime=end,
            ):
                for e in page.get("Events", []):
                    try:
                        raw_events.append(json.loads(e.get("CloudTrailEvent", "{}")))
                    except Exception:
                        pass
        return raw_events
    except Exception as exc:
        logger.warning("CloudTrail fetch failed (%s) — falling back to mock events", exc)
        return get_mock_events()


def watch(callback: callable, poll_interval: int = 30) -> None:
    seen: set[str] = set()
    logger.info("CloudTrail watch started (interval=%ds)", poll_interval)
    while True:
        try:
            for raw in fetch_recent_events(hours=1):
                claim = normalise(raw)
                if claim and claim.event_id not in seen:
                    seen.add(claim.event_id)
                    logger.info("New event: %s from %s", claim.event_type, claim.actor_email)
                    try:
                        callback(claim)
                    except Exception as exc:
                        logger.warning("Callback error for %s: %s", claim.event_id, exc)
        except Exception as exc:
            logger.error("Watch loop error: %s", exc)
        time.sleep(poll_interval)
