import json, time, logging
from datetime import datetime, timezone
from pathlib import Path
from .schema import ClaimSet, AuthMethod, EventType

logger = logging.getLogger(__name__)

WATCHED_EVENTS: set[str] = {
    "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
    "AttachRolePolicy", "DetachRolePolicy", "CreateAccessKey",
    "DeleteAccessKey", "PutBucketPolicy", "StopLogging",
    "DeleteTrail", "AuthorizeSecurityGroupIngress",
    "ModifyDBInstance", "CreatePolicy", "DeletePolicy"
}

HIGH_SEVERITY_EVENTS: set[str] = {
    "StopLogging", "DeleteTrail", "DeleteUser", "DeletePolicy"
}


def is_human_actor(user_identity: dict) -> bool:
    id_type = user_identity.get("type", "")
    if id_type in ("IAMUser", "Root", "FederatedUser"):
        return True
    if id_type == "AssumedRole":
        issuer = (user_identity.get("sessionContext") or {}).get("sessionIssuer") or {}
        return issuer.get("type", "") not in ("Service", "AWS", "AWSService")
    return False


def extract_auth_method(event: dict) -> AuthMethod:
    additional = event.get("additionalEventData") or {}
    identity = event.get("userIdentity") or {}
    attrs = ((identity.get("sessionContext") or {}).get("attributes") or {})
    event_name = event.get("eventName", "")

    if event_name == "ConsoleLogin":
        if additional.get("MFAUsed", "No") == "Yes":
            mfa_id = additional.get("MFAIdentifier", "").lower()
            if any(tok in mfa_id for tok in ("u2f", "fido", "webauthn")):
                return "FIDO2"
            return "TOTP"
        return "PASSWORD"

    if attrs.get("mfaAuthenticated") == "true":
        return "TOTP"
    return "UNKNOWN"


def extract_actor_email(user_identity: dict) -> str:
    username = user_identity.get("userName", "")
    if username:
        return username
    arn = user_identity.get("arn", "")
    if "/" in arn:
        return arn.split("/")[-1]
    return "unknown"


def _session_age(event: dict, event_ts: int) -> int:
    attrs = (
        ((event.get("userIdentity") or {}).get("sessionContext") or {})
        .get("attributes") or {}
    )
    creation_str = attrs.get("creationDate", "")
    if not creation_str:
        return 0
    try:
        dt = datetime.fromisoformat(creation_str.replace("Z", "+00:00"))
        return max(0, event_ts - int(dt.timestamp()))
    except Exception:
        return 0


def _resource(event: dict) -> str:
    resources = event.get("resources") or []
    if resources:
        return resources[0].get("ARN", "unknown")
    params = event.get("requestParameters") or {}
    if event.get("eventName") == "AssumeRole":
        return params.get("roleArn", "unknown")
    return "unknown"


def normalise(raw: dict) -> ClaimSet | None:
    event_name = raw.get("eventName", "")
    if event_name not in WATCHED_EVENTS:
        return None
    try:
        event_id = raw.get("eventID", "")
        if not event_id:
            logger.warning("Skipping event with missing eventID")
            return None

        identity = raw.get("userIdentity") or {}

        try:
            dt = datetime.fromisoformat(
                raw.get("eventTime", "").replace("Z", "+00:00")
            )
            timestamp = int(dt.timestamp())
        except Exception:
            logger.warning("Invalid eventTime for %s; using current time", event_id)
            timestamp = int(time.time())

        auth_method = extract_auth_method(raw)

        return ClaimSet(
            event_id=event_id,
            event_type=event_name,
            actor_arn=identity.get("arn", "unknown"),
            actor_email=extract_actor_email(identity),
            action=event_name,
            resource=_resource(raw),
            timestamp=timestamp,
            source_region=raw.get("awsRegion", "unknown"),
            source_ip=raw.get("sourceIPAddress", "unknown"),
            mfa_used=auth_method in ("FIDO2", "TOTP"),
            auth_method=auth_method,
            session_age_seconds=_session_age(raw, timestamp),
            is_root=identity.get("type") == "Root",
            is_human=is_human_actor(identity),
            raw_hash=ClaimSet.hash_event(raw),
        )
    except Exception as exc:
        logger.warning("Failed to normalise %s: %s", raw.get("eventID", "?"), exc)
        return None


def normalise_file(path: str) -> list[ClaimSet]:
    data = json.loads(Path(path).read_text())
    raw_events = data if isinstance(data, list) else data.get("Records", [])
    return [c for raw in raw_events if (c := normalise(raw)) is not None]
