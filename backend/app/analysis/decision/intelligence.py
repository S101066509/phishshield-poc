# 檔案功能：驗證應用端提供的簽章網址情報、可信來源與有效期，預設不提供惡意情報。

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Literal, Protocol

from pydantic import Field, model_validator

from app.domain.decision_models import OverrideAudit
from app.domain.email_models import Contract, NormalizedEmail


class SignedIndicator(Contract):
    rule_id: str = Field(pattern=r"^[A-Z][A-Z0-9_]{0,63}$")
    rule_version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    source_id: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")
    source_version: str = Field(min_length=1, max_length=80)
    kind: Literal["url"] = "url"
    target: str = Field(min_length=1, max_length=8192)
    evidence_ref: str = Field(pattern=r"^url:(0|[1-9]\d*)$")
    verdict: Literal["malicious"] = "malicious"
    issued_at: datetime
    expires_at: datetime
    signature: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def validate_time(self):
        if (
            self.issued_at.utcoffset() is None
            or self.expires_at.utcoffset() is None
            or self.expires_at <= self.issued_at
        ):
            raise ValueError("INVALID_INTELLIGENCE_TIME")
        return self


class IntelligencePolicy(Protocol):
    def claims_for(self, email: NormalizedEmail) -> Sequence[SignedIndicator]: ...


class NoIntelligence:
    def claims_for(self, email):
        return ()


def claim_payload(claim: SignedIndicator) -> bytes:
    return json.dumps(
        claim.model_dump(mode="json", exclude={"signature"}),
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()


class TrustStore:
    """Only constructed by application code; never populated from model/mail/API fields."""

    def __init__(self, keys: Mapping[tuple[str, str], bytes] | None = None):
        self._keys = dict(keys or {})
        if any(not isinstance(key, bytes) or len(key) < 32 for key in self._keys.values()):
            raise ValueError("VERIFICATION_KEY_TOO_SHORT")

    def verify(
        self, raw: SignedIndicator, email: NormalizedEmail, now: datetime
    ) -> OverrideAudit | None:
        try:
            claim = SignedIndicator.model_validate(raw.model_dump())
            key = self._keys.get((claim.source_id, claim.source_version))
            if key is None or not claim.issued_at <= now < claim.expires_at:
                return None
            expected = hmac.new(key, claim_payload(claim), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, claim.signature):
                return None
            index = int(claim.evidence_ref.split(":")[1])
            if index >= len(email.urls):
                return None
            url = email.urls[index]
            if url.boundary_ambiguous or url.parse_warning or not url.normalized_url:
                return None
            if claim.target != url.normalized_url:
                return None
            return OverrideAudit(
                rule_id=claim.rule_id,
                rule_version=claim.rule_version,
                source_id=claim.source_id,
                source_version=claim.source_version,
                evidence_ref=claim.evidence_ref,
                target_sha256=hashlib.sha256(claim.target.encode()).hexdigest(),
                issued_at=claim.issued_at,
                expires_at=claim.expires_at,
                verified_at=now,
            )
        except (ValueError, TypeError, AttributeError):
            return None
