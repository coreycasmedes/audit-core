from pydantic import BaseModel
from typing import Literal
import hashlib, json

AuthMethod = Literal["FIDO2", "TOTP", "PASSWORD", "UNKNOWN"]
EventType = Literal[
    "ConsoleLogin", "AssumeRole", "CreateUser", "DeleteUser",
    "AttachRolePolicy", "DetachRolePolicy", "CreateAccessKey",
    "DeleteAccessKey", "PutBucketPolicy", "StopLogging",
    "DeleteTrail", "AuthorizeSecurityGroupIngress",
    "ModifyDBInstance", "CreatePolicy", "DeletePolicy", "OTHER"
]

_BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617


class ClaimSet(BaseModel):
    event_id: str
    event_type: EventType
    actor_arn: str
    actor_email: str
    action: str
    resource: str
    timestamp: int
    source_region: str
    source_ip: str
    mfa_used: bool
    auth_method: AuthMethod
    session_age_seconds: int
    is_root: bool
    is_human: bool
    raw_hash: str

    @classmethod
    def hash_event(cls, raw: dict) -> str:
        return hashlib.sha256(
            json.dumps(raw, sort_keys=True).encode()
        ).hexdigest()

    def to_proof_inputs(self) -> dict:
        auth_enc = {"FIDO2": 1, "TOTP": 2, "PASSWORD": 3, "UNKNOWN": 0}
        actor_hash = int(hashlib.sha256(self.actor_arn.encode()).hexdigest(), 16) % _BN254_PRIME
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "actor_arn_hash": actor_hash,
            "timestamp": self.timestamp,
            "mfa_used": 1 if self.mfa_used else 0,
            "auth_method": auth_enc[self.auth_method],
            "is_root": 1 if self.is_root else 0,
            "is_human": 1 if self.is_human else 0,
            "source_region": self.source_region,
        }
