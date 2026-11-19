# 檔案功能：定義規則介面與訊號規則實作，將命中證據轉為結構化規則發現。

from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol

from app.domain.analysis_models import RuleFinding
from app.domain.email_models import NormalizedEmail


class Rule(Protocol):
    id: str
    version: str

    def evaluate(self, email: NormalizedEmail) -> list[RuleFinding]: ...


@dataclass(frozen=True)
class SignalRule:
    id: str
    category: Literal["email_threat", "prompt_injection"]
    severity: Literal["low", "medium", "high", "critical"]
    summary: str
    detector: Callable[[NormalizedEmail], list[str]]
    version: str = "1.0.0"

    def evaluate(self, email: NormalizedEmail) -> list[RuleFinding]:
        references = list(dict.fromkeys(self.detector(email)))
        if not references:
            return []
        return [
            RuleFinding(
                rule_id=self.id,
                rule_version=self.version,
                category=self.category,
                severity=self.severity,
                evidence_refs=references,
                summary=self.summary,
                evidence_source="parsed_email",
                is_confirmed_malicious=False,
            )
        ]
