# 檔案功能：驗證必要分析與證據後產生最終分類，保留覆核需求並執行可信情報覆蓋。

from datetime import UTC, datetime
from itertools import islice
from uuid import UUID, uuid4

from app.analysis.decision.intelligence import IntelligencePolicy, NoIntelligence, TrustStore
from app.analysis.llm.evidence_catalog import evidence_catalog
from app.analysis.rules import RuleEngine
from app.analysis.rules.models import RuleRun
from app.domain.analysis_models import AnalysisError, AnalysisVersions
from app.domain.decision_models import DecisionResult
from app.domain.email_models import NormalizedEmail, ReviewItem
from app.domain.evidence import EvidenceRegistry
from app.domain.llm_models import LLMRun
from app.domain.stage_failure import REASONS, StageFailure
from app.domain.versions import (
    LLM_PIPELINE_VERSION,
    LLM_SCHEMA_VERSION,
    PARSER_VERSION,
    RULESET_VERSION,
    prompt_versions_for,
)


def _unexecuted_versions(failure=None):
    if failure is not None and getattr(failure, "versions", None) is not None:
        return failure.versions.model_copy(deep=True)
    return AnalysisVersions(
        parser=PARSER_VERSION,
        ruleset=RULESET_VERSION if failure is None or failure.phase > 1 else "not_executed",
        prompt_a="not_executed",
        prompt_b="not_executed",
        model_a="not_executed",
        model_b="not_executed",
    )


def failed_decision(
    code: str, *, analysis_id: UUID | None = None, phase=4, versions=None
) -> DecisionResult:
    if code not in REASONS and code not in {
        "INVALID_DECISION_INPUT",
        "INVALID_DECISION_CLOCK",
        "INTELLIGENCE_UNAVAILABLE",
        "REQUIRED_STAGE_FAILED",
        "ANALYSIS_SERVICE_FAILED",
        "ANALYSIS_TIMEOUT",
    }:
        code = "REQUIRED_STAGE_FAILED"
    return DecisionResult(
        analysis_id=analysis_id or uuid4(),
        status="FAILED",
        final_classification="UNKNOWN",
        reason_codes=[code],
        errors=[AnalysisError(code=code)],
        failed_phase=phase,
        versions=versions or _unexecuted_versions(),
        review_items=[ReviewItem(code=code, message="未成功完成分析，需重新提交或人工判讀。")],
    )


def retain_rule_context(result, email, rules):
    """A failed later stage must not erase independently validated rule observations."""
    if result.status != "FAILED" or result.rule_findings:
        return result
    try:
        if not isinstance(email, NormalizedEmail) or not isinstance(rules, RuleRun):
            return result
        mail = NormalizedEmail.model_validate_json(
            email.model_dump_json(exclude_computed_fields=True), strict=True
        )
        run = RuleRun.model_validate_json(
            rules.model_dump_json(exclude_computed_fields=True), strict=True
        )
        if (
            mail.parser_version != PARSER_VERSION
            or run.parser_version != PARSER_VERSION
            or run.ruleset_version != RULESET_VERSION
            or run.content_hash != mail.content_hash
        ):
            return result
        # Recompute against this mail: no forged rule/version/evidence context is retained.
        if RuleEngine().analyze(mail) != run:
            return result
        registry = EvidenceRegistry(mail)
        refs = list(
            dict.fromkeys(
                ref for item in [*run.findings, *run.review_items] for ref in item.evidence_refs
            )
        )
        registry.validate(refs)
        return result.model_copy(
            update={
                "rule_findings": run.findings,
                "evidence_refs": refs,
                "parse_warnings": mail.parse_warnings,
                "review_items": [*result.review_items, *run.review_items],
            }
        )
    except Exception:
        return result


def _validate(email, rules, llm):
    if (
        not isinstance(email, NormalizedEmail)
        or not isinstance(rules, RuleRun)
        or not isinstance(llm, LLMRun)
    ):
        raise ValueError("INVALID_DECISION_INPUT")
    mail = NormalizedEmail.model_validate_json(
        email.model_dump_json(exclude_computed_fields=True), strict=True
    )
    run = RuleRun.model_validate_json(
        rules.model_dump_json(exclude_computed_fields=True), strict=True
    )
    model = LLMRun.model_validate_json(
        llm.model_dump_json(exclude_computed_fields=True), strict=True
    )
    if (
        mail.parser_version != PARSER_VERSION
        or run.parser_version != mail.parser_version
        or run.ruleset_version != RULESET_VERSION
        or model.pipeline_version != LLM_PIPELINE_VERSION
        or model.schema_version != LLM_SCHEMA_VERSION
        or model.versions.llm_pipeline != model.pipeline_version
        or model.versions.llm_schema != model.schema_version
        or model.versions.parser != mail.parser_version
        or model.versions.ruleset != run.ruleset_version
        or model.content_hash != mail.content_hash
        or run.content_hash != mail.content_hash
        or model.rules != run
        or model.simulation is None
    ):
        raise ValueError("MISMATCHED_STAGES")
    if (model.versions.prompt_a, model.versions.prompt_b) != prompt_versions_for(
        model.analysis_method, model.judgment_format
    ):
        raise ValueError("MISMATCHED_PROMPTS")
    registry = EvidenceRegistry(mail)
    known = RuleEngine().rule_versions
    if any(known.get(key) != value for key, value in run.rule_versions.items()):
        raise ValueError("INVALID_RULE_VERSION")
    for item in run.findings:
        if (
            item.is_confirmed_malicious
            or not item.evidence_refs
            or run.rule_versions.get(item.rule_id) != item.rule_version
        ):
            raise ValueError("INVALID_RULE_FINDING")
        registry.validate(item.evidence_refs)
    if any(item not in run.review_items for item in mail.review_items) or any(
        item not in model.review_items for item in run.review_items
    ):
        raise ValueError("DROPPED_REVIEW")
    for item in [*mail.review_items, *run.review_items, *model.review_items]:
        registry.validate(item.evidence_refs)
    if model.analysis_method == "single" and (
        model.versions.prompt_a != "not_executed"
        or model.versions.model_a != "not_executed"
        or model.features.features
        or model.features.observations
        or model.features.suspicious_url_refs
        or model.features.uncertainties
        or model.features.scope_limitations
        or model.features.social_engineering_indicators
    ):
        raise ValueError("SINGLE_MODEL_CANNOT_CLAIM_EXTRACTION")
    event_fields = (
        model.event_extraction,
        model.event_handoff,
        model.event_evidence_map,
        model.event_decision_core,
    )
    if model.analysis_method == "structured_event_dual":
        from app.analysis.llm.event_handoff import event_review_items, validate_event_run

        if (
            model.judgment_format != "event_facts_core_1"
            or model.handoff is not None
            or model.structured_judgment is not None
            or model.handoff_evidence_map
            or model.decision_core is not None
            or model.features.features
            or model.features.observations is not None
            or model.features.suspicious_url_refs
            or model.features.social_engineering_indicators
            or model.features.uncertainties
            or model.features.scope_limitations
        ):
            raise ValueError("MISMATCHED_EVENT_METHOD")
        packet, handoff_refs = validate_event_run(mail, run, model)
        if any(
            item not in model.review_items
            for item in event_review_items(packet, model.event_evidence_map)
        ):
            raise ValueError("DROPPED_EVENT_REVIEW")
    elif any(event_fields):
        raise ValueError("MISMATCHED_EVENT_METHOD")
    elif model.analysis_method == "structured_dual":
        from app.analysis.llm.handoff import validate_run

        if model.judgment_format not in {"core_slots_1", "proposal_v1"} or (
            model.judgment_format == "proposal_v1" and model.decision_core is not None
        ):
            raise ValueError("MISMATCHED_JUDGMENT_FORMAT")
        _, handoff_refs = validate_run(mail, run, model)
    elif (
        model.handoff is not None
        or model.structured_judgment is not None
        or model.handoff_evidence_map
        or model.judgment_format is not None
        or model.decision_core is not None
    ):
        raise ValueError("MISMATCHED_ANALYSIS_METHOD")
    allowed = set(evidence_catalog(mail)) | {
        ref for item in [*run.findings, *run.review_items] for ref in item.evidence_refs
    }
    for item in model.features.features:
        registry.validate(item.evidence_refs)
        allowed.update(item.evidence_refs)
    registry.validate(model.features.suspicious_url_refs)
    if any(not ref.startswith("url:") for ref in model.features.suspicious_url_refs):
        raise ValueError("INVALID_URL_REFERENCE")
    allowed.update(model.features.suspicious_url_refs)
    judgment_refs = model.judgment.evidence_refs + [
        ref for item in model.judgment.explanations for ref in item.evidence_refs
    ]
    if model.analysis_method in {"structured_dual", "structured_event_dual"}:
        allowed = handoff_refs
    registry.validate(judgment_refs)
    if not set(judgment_refs) <= allowed:
        raise ValueError("UNSEEN_JUDGMENT_EVIDENCE")
    if [call.stage for call in model.calls if call.error_code is None] != (
        ["b"] if model.analysis_method == "single" else ["a", "b"]
    ):
        raise ValueError("REQUIRED_MODEL_STAGE_MISSING")
    if not model.calls or model.calls[-1].stage != "b" or model.calls[-1].error_code:
        raise ValueError("MODEL_STAGE_INCOMPLETE")
    seen_b = False
    attempts = {"a": 0, "b": 0}
    endpoints = {"a": (1, 0), "b": (1, 0)}
    for call in model.calls:
        if seen_b and call.stage == "a":
            raise ValueError("INVALID_STAGE_ORDER")
        seen_b |= call.stage == "b"
        attempts[call.stage] += 1
        if call.attempt != attempts[call.stage]:
            raise ValueError("INVALID_ATTEMPT_ORDER")
        if call.endpoint_index is not None or call.endpoint_attempt is not None:
            previous_index, previous_attempt = endpoints[call.stage]
            expected = previous_attempt + 1 if call.endpoint_index == previous_index else 1
            if (
                call.endpoint_index not in {previous_index, previous_index + 1}
                or call.endpoint_attempt != expected
                or (previous_attempt == 0 and call.endpoint_index != 1)
            ):
                raise ValueError("INVALID_ENDPOINT_ORDER")
            endpoints[call.stage] = (call.endpoint_index, call.endpoint_attempt)
        if (
            call.error_code is None
            and call.model_id is not None
            and (call.model_id != getattr(model.versions, "model_" + call.stage))
        ):
            raise ValueError("MISMATCHED_EXECUTED_MODEL")
    return mail, run, model


def finalize_analysis(
    email,
    rules,
    llm,
    *,
    analysis_id: UUID | None = None,
    policy: IntelligencePolicy | None = None,
    trust_store: TrustStore | None = None,
    now: datetime | None = None,
) -> DecisionResult:
    identifier = analysis_id or uuid4()
    for stage in (email, rules, llm):
        if isinstance(stage, StageFailure):
            return retain_rule_context(
                failed_decision(
                    stage.error_code,
                    analysis_id=identifier,
                    phase=stage.phase,
                    versions=_unexecuted_versions(stage),
                ),
                email,
                rules,
            )
    try:
        mail, run, model = _validate(email, rules, llm)
    except Exception:
        return retain_rule_context(
            failed_decision("INVALID_DECISION_INPUT", analysis_id=identifier), email, rules
        )
    now = now or datetime.now(UTC)
    if not isinstance(now, datetime) or now.utcoffset() is None:
        return failed_decision(
            "INVALID_DECISION_CLOCK", analysis_id=identifier, versions=model.versions
        )
    # Generic scope limitations are reported separately, never treated as risk evidence.
    # Explicit message-risk uncertainties, parser warnings and rule findings still block SAFE.
    reviews = [item.model_copy(deep=True) for item in model.review_items]
    uncertainties = list(model.judgment.uncertainties)
    if model.analysis_method == "legacy_dual":
        uncertainties.extend(model.features.uncertainties)
    elif model.analysis_method == "structured_dual" and (
        any(item.assessment == "uncertain" for item in model.handoff.observations)
        or not model.handoff.rules_complete
    ):
        uncertainties.append("UNMAPPED_CONTENT")
    elif model.analysis_method == "structured_event_dual" and (
        model.event_handoff.semantic_completeness != "complete"
        or not model.event_handoff.rules_complete
    ):
        uncertainties.append("SEMANTIC_EXTRACTION_INCOMPLETE")
    for uncertainty in uncertainties:
        item = ReviewItem(code="LLM_UNCERTAINTY", message=uncertainty)
        if item not in reviews:
            reviews.append(item)
    classification = model.judgment.classification
    reasons = ["MODEL_RECOMMENDATION", *model.judgment.reason_codes]
    audit = None
    simulation = model.is_simulation
    if simulation:
        classification, reasons = "UNKNOWN", ["SIMULATED_ANALYSIS"]
        reviews.append(
            ReviewItem(code="SIMULATED_ANALYSIS", message="離線模擬不構成真實郵件風險判斷。")
        )
    else:
        try:
            claims = tuple(islice((policy or NoIntelligence()).claims_for(mail), 101))
            if len(claims) > 100:
                raise ValueError("INTELLIGENCE_LIMIT")
            verifier = trust_store or TrustStore()
            for claim in claims:
                candidate = verifier.verify(claim, mail, now)
                if candidate is not None and audit is None:
                    audit = candidate
                elif candidate is None:
                    reviews.append(
                        ReviewItem(
                            code="UNVERIFIED_INTELLIGENCE",
                            message="情報來源、簽章、有效期或網址證據未通過驗證。",
                        )
                    )
        except Exception:
            return failed_decision(
                "INTELLIGENCE_UNAVAILABLE", analysis_id=identifier, versions=model.versions
            )
        if audit is not None:
            classification, reasons = "PHISHING", ["TRUSTED_MALICIOUS_URL"]
        elif classification == "SAFE" and (reviews or mail.parse_warnings or run.findings):
            classification, reasons = "UNKNOWN", ["EVIDENCE_INSUFFICIENT", "REVIEW_REQUIRED"]
    evidence = list(
        dict.fromkeys(
            [
                *model.judgment.evidence_refs,
                *[ref for item in model.judgment.explanations for ref in item.evidence_refs],
                *([audit.evidence_ref] if audit else []),
            ]
        )
    )
    usage = None
    if model.calls and all(call.usage is not None for call in model.calls):
        usage = sum(call.usage.input_tokens + call.usage.output_tokens for call in model.calls)
    return DecisionResult(
        analysis_id=identifier,
        status="COMPLETED",
        final_classification=classification,
        llm_classification=model.judgment.classification,
        reason_codes=list(dict.fromkeys(reasons)),
        rule_findings=run.findings,
        override_applied=audit is not None,
        override_rule_id=audit.rule_id if audit else None,
        override_audit=audit,
        evidence_refs=evidence,
        parse_warnings=mail.parse_warnings,
        versions=model.versions,
        token_usage=usage,
        estimated_cost=None,
        review_items=reviews,
        simulation=simulation,
    )
