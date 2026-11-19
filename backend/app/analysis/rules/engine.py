# 檔案功能：管理規則註冊與執行，驗證命中證據並保留人工覆核和受控失敗。

from collections.abc import Iterable

from pydantic import ValidationError

from app.analysis.rules.base import Rule
from app.analysis.rules.injection_rules import injection_rules
from app.analysis.rules.models import RuleRun
from app.analysis.rules.text import text_context
from app.analysis.rules.threat_rules import threat_rules
from app.domain.analysis_models import RuleFinding
from app.domain.email_models import NormalizedEmail, ReviewItem
from app.domain.evidence import EvidenceRegistry
from app.domain.stage_failure import StageFailure, stage_failure
from app.domain.versions import RULESET_VERSION


class RuleEvaluationError(Exception):
    def __init__(self, rule_id: str):
        self.rule_id = rule_id
        self.code = "RULE_EVALUATION_FAILED"
        super().__init__(self.code)


class RuleEngine:
    version = RULESET_VERSION

    def __init__(
        self, rules: Iterable[Rule] | None = None, *, enabled_ids: Iterable[str] | None = None
    ):
        registered = tuple(rules) if rules is not None else threat_rules() + injection_rules()
        identifiers = [rule.id for rule in registered]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("DUPLICATE_RULE_ID")
        enabled = set(identifiers) if enabled_ids is None else set(enabled_ids)
        if enabled - set(identifiers):
            raise ValueError("UNKNOWN_RULE_ID")
        # Selection never changes registry evaluation order.
        self.rules = tuple(rule for rule in registered if rule.id in enabled)

    @property
    def rule_versions(self) -> dict[str, str]:
        return {rule.id: rule.version for rule in self.rules}

    def evaluate(self, email: NormalizedEmail) -> list[RuleFinding]:
        with text_context(email):
            return self._evaluate(email)

    def _evaluate(self, email: NormalizedEmail) -> list[RuleFinding]:
        registry = EvidenceRegistry(email)
        findings = []
        for rule in self.rules:
            try:
                for finding in rule.evaluate(email):
                    validated = RuleFinding.model_validate(finding.model_dump())
                    if (
                        validated.rule_id != rule.id
                        or validated.rule_version != rule.version
                        or validated.is_confirmed_malicious
                        or not validated.evidence_refs
                    ):
                        raise ValueError("INVALID_RULE_OUTPUT")
                    registry.validate(validated.evidence_refs)
                    findings.append(validated)
            except Exception:
                # No partial successful output and no raw mail/traceback in error messages.
                raise RuleEvaluationError(rule.id) from None
        return findings

    def analyze(self, email: NormalizedEmail) -> RuleRun:
        findings = self.evaluate(email)
        reviews = [item.model_copy(deep=True) for item in email.review_items]
        reviews.extend(
            ReviewItem(
                code=finding.rule_id,
                message=f"規則訊號需人工判讀，不代表已證實釣魚：{finding.summary}",
                evidence_refs=list(finding.evidence_refs),
            )
            for finding in findings
        )
        return RuleRun(
            parser_version=email.parser_version,
            ruleset_version=self.version,
            rule_versions=self.rule_versions,
            content_hash=email.content_hash,
            findings=findings,
            review_items=reviews,
        )

    def analyze_result(self, email: NormalizedEmail | StageFailure) -> RuleRun | StageFailure:
        if isinstance(email, StageFailure):
            # A failed parser must never be processed as a clean, empty email.
            return email
        if not isinstance(email, NormalizedEmail):
            return stage_failure(2, "INVALID_RULE_INPUT")
        try:
            snapshot = NormalizedEmail.model_validate(
                email.model_dump(exclude_computed_fields=True)
            )
            registry = EvidenceRegistry(snapshot)
            for item in snapshot.review_items:
                registry.validate(item.evidence_refs)
        except (ValidationError, ValueError, TypeError):
            return stage_failure(2, "INVALID_RULE_INPUT")
        try:
            return self.analyze(snapshot)
        except RuleEvaluationError as exc:
            return stage_failure(2, exc.code, rule_id=exc.rule_id)
