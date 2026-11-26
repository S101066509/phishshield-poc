# 檔案功能：逐欄投影封閉觀察、核發本次引用，驗證 B 判斷與可見證據的對應。
import ipaddress
from uuid import uuid4

from pydantic import Field, model_validator

from app.analysis.llm.compact_input import coverage_for_mail
from app.analysis.llm.evidence_catalog import evidence_catalog
from app.analysis.llm.reason_support import (
    SUPPORT,
    validate_bound_support,
    validate_flat_support,
)
from app.analysis.rules import RuleEngine
from app.domain.email_models import Contract
from app.domain.handoff_models import (
    KINDS,
    Assessment,
    JudgeInput,
    JudgeObservation,
    Observation,
    Reference,
)
from app.domain.handoff_models import StructuredJudgment as Judgment
from app.domain.llm_models import FeatureOutput, JudgmentOutput, RiskExplanation

AUTHENTICATION_HEADERS = ("authentication-results", "received-spf", "dkim-signature")
AUTHENTICATION_REFERENCE_PREFIXES = tuple(f"header:{name}:" for name in AUTHENTICATION_HEADERS)


class SlotObservation(Contract):
    assessment: Assessment
    evidence_refs: list[Reference] = Field(max_length=100)


class ObservationSlots(Contract):
    authentication: SlotObservation
    credential_request: SlotObservation
    urgency_fear: SlotObservation
    impersonation: SlotObservation
    generic_salutation: SlotObservation
    url_deception: SlotObservation
    language: SlotObservation
    analysis_override: SlotObservation


class SlotExtraction(Contract):
    """Model wire format; Python assigns kind names, never infers missing observations."""

    observations: ObservationSlots


class Extraction(FeatureOutput):
    observations: list[Observation] = Field(min_length=8, max_length=8)

    @model_validator(mode="after")
    def complete(self):
        if {item.kind for item in self.observations} != set(KINDS):
            raise ValueError("INCOMPLETE_OBSERVATIONS")
        for item in self.observations:
            if item.assessment != "not_applicable" and not item.evidence_refs:
                raise ValueError("OBSERVATION_REQUIRES_REFERENCE")
            if (
                item.kind not in {"url_deception", "authentication"}
                and item.assessment == "not_applicable"
            ):
                raise ValueError("INVALID_APPLICABILITY")
        return self


def validate_native_extraction(value, *, has_urls, has_authentication):
    for item in value.observations:
        absent = (item.kind == "url_deception" and not has_urls) or (
            item.kind == "authentication" and not has_authentication
        )
        if absent and (item.assessment != "not_applicable" or item.evidence_refs):
            raise ValueError("INVALID_APPLICABILITY")
        if not absent and item.assessment == "not_applicable":
            raise ValueError("INVALID_APPLICABILITY")
        if len(item.evidence_refs) > 4:
            raise ValueError("INVALID_OBSERVATION_REFERENCE")
        # 僅風險正向／歧義觀察須含對應種類；陰性查閱與額外正文引用保持原義。
        # 現有生成Schema子集不能在混合陣列表示contains，因此這是獨立runtime必要條件。
        if item.assessment in {"observed", "uncertain"}:
            prefixes = (
                ("url:",)
                if item.kind == "url_deception"
                else AUTHENTICATION_REFERENCE_PREFIXES
                if item.kind == "authentication"
                else ()
            )
            if prefixes and not any(ref.startswith(prefixes) for ref in item.evidence_refs):
                raise ValueError("INVALID_OBSERVATION_REFERENCE")


def _ip(host):
    try:
        ipaddress.ip_address(host or "")
        return True
    except ValueError:
        return False


def project(mail, rules, extraction, *, scope_id=None, coverage=None, native=False):
    extraction = Extraction.model_validate_json(
        extraction.model_dump_json(exclude_computed_fields=True), strict=True
    )
    if native:
        validate_native_extraction(
            extraction,
            has_urls=bool(mail.urls),
            has_authentication=any(mail.headers.get(name) for name in AUTHENTICATION_HEADERS),
        )
    catalog = evidence_catalog(mail)
    attachment_refs = sorted(
        {
            ref
            for finding in rules.findings
            if finding.rule_id == "EMAIL_ATTACHMENT_EXTENSION"
            for ref in finding.evidence_refs
        }
    )
    references = sorted(
        {ref for item in extraction.observations for ref in item.evidence_refs}
        | set(attachment_refs)
    )
    if not set(references) <= set(catalog) or len(references) > 999:
        raise ValueError("INVALID_OBSERVATION_REFERENCE")
    # Recompute registered signals instead of trusting supplied summaries/flags.
    if RuleEngine(enabled_ids=rules.rule_versions).analyze(mail) != rules:
        raise ValueError("INVALID_RULE_CONTEXT")
    scope_id = scope_id or uuid4().hex[:16]
    forward = {ref: f"e_{scope_id}_{index:03d}" for index, ref in enumerate(references, 1)}
    risky_attachment_ids = tuple(sorted({forward[ref] for ref in attachment_refs}))
    observations = []
    by_kind = {item.kind: item for item in extraction.observations}
    for index, kind in enumerate(KINDS, 1):
        item = by_kind[kind]
        if item.assessment == "not_applicable":
            if (kind == "url_deception" and mail.urls) or (
                kind == "authentication"
                and any(mail.headers.get(name) for name in AUTHENTICATION_HEADERS)
            ):
                raise ValueError("INVALID_APPLICABILITY")
        observations.append(
            JudgeObservation(
                id=f"f_{scope_id}_{index:03d}",
                kind=kind,
                assessment=item.assessment,
                evidence_ids=tuple(sorted({forward[ref] for ref in item.evidence_refs})),
            )
        )
    identifiers = {item.rule_id for item in rules.findings}
    packet = JudgeInput(
        contract="structured_handoff_2" if coverage is not None else "structured_handoff_1",
        scope_id=scope_id,
        observations=tuple(observations),
        url_count=len(mail.urls),
        attachment_count=len(mail.attachments_metadata),
        url_userinfo_present=any(
            "@" in (url.normalized_url or "").split("://", 1)[-1].split("/", 1)[0]
            for url in mail.urls
        ),
        url_ip_host_present=any(_ip(url.hostname) for url in mail.urls),
        risky_attachment_extension="EMAIL_ATTACHMENT_EXTENSION" in identifiers,
        risky_attachment_evidence_ids=risky_attachment_ids,
        credential_rule_observed="EMAIL_CREDENTIAL_REQUEST" in identifiers,
        urgency_rule_observed="EMAIL_URGENCY" in identifiers,
        injection_rule_observed=any(key.startswith("INJECTION_") for key in identifiers),
        rules_complete=rules.rule_versions == RuleEngine().rule_versions,
        rule_count=len(rules.findings),
        parser_warning_count=len(mail.parse_warnings),
        review_required=bool(rules.review_items),
        coverage=coverage or coverage_for_mail(mail),
    )
    return packet, {value: key for key, value in forward.items()}


def allowed_uncertainties(packet, *, simulation=False):
    uncertain = {item.kind for item in packet.observations if item.assessment == "uncertain"}
    codes = []
    if uncertain & {"credential_request", "urgency_fear"}:
        codes.append("AMBIGUOUS_REQUEST")
    if uncertain & {"authentication", "impersonation"}:
        codes.append("AMBIGUOUS_IDENTITY")
    if "url_deception" in uncertain:
        codes.append("AMBIGUOUS_URL")
    if uncertain or not packet.rules_complete:
        codes.append("UNMAPPED_CONTENT")
    if simulation:
        codes.append("SIMULATION")
    return codes


def validate_judgment(value, packet, mapping, *, simulation=False):
    if packet.coverage.status == "incomplete" and (
        value.classification == "SAFE" or "NO_RISK_OBSERVED" in value.reason_codes
    ):
        raise ValueError("INCOMPLETE_COVERAGE")
    if not set(value.uncertainty_codes) <= set(
        allowed_uncertainties(packet, simulation=simulation)
    ):
        raise ValueError("UNSUPPORTED_UNCERTAINTY")
    if not simulation and "SIMULATED_ANALYSIS" in value.reason_codes:
        raise ValueError("INVALID_SIMULATION_CLAIM")
    validate_bound_support(value, packet)
    observations = {item.id: item for item in packet.observations}
    if not set(value.supporting_observation_ids) <= set(observations):
        raise ValueError("INVALID_OBSERVATION")
    selected = [observations[key] for key in value.supporting_observation_ids]
    allowed = {ref for item in selected for ref in item.evidence_ids}
    attachment_allowed = (
        set(packet.risky_attachment_evidence_ids) if packet.risky_attachment_extension else set()
    )
    refs = value.evidence_refs + [ref for item in value.explanations for ref in item.evidence_refs]
    if not set(refs) <= set(mapping):
        raise ValueError("INVALID_EVIDENCE")
    validate_flat_support(value, packet)
    has_model_support = bool(selected and (set(value.evidence_refs) & allowed))
    has_attachment_support = bool(
        "RISKY_ATTACHMENT" in value.reason_codes
        and attachment_allowed
        and (set(value.evidence_refs) & attachment_allowed)
    )
    if value.classification != "UNKNOWN" and not (has_model_support or has_attachment_support):
        raise ValueError("INSUFFICIENT_SUPPORT")
    if "NO_RISK_OBSERVED" in value.reason_codes and any(
        item.assessment in {"observed", "uncertain"} for item in packet.observations
    ):
        raise ValueError("CONTRADICTORY_REASON")
    if value.classification == "SAFE" and value.reason_codes != ["NO_RISK_OBSERVED"]:
        raise ValueError("UNSUPPORTED_SAFE")
    url_obs = next((item for item in packet.observations if item.kind == "url_deception"), None)
    weak_uncertain_url = (
        url_obs is not None
        and url_obs.assessment == "uncertain"
        and not packet.url_userinfo_present
        and not packet.url_ip_host_present
    )
    has_model_risk = any(
        code in SUPPORT
        and code != "AUTHENTICATION_UNVERIFIED"
        and not (code == "URL_DECEPTION" and weak_uncertain_url)
        for code in value.reason_codes
    )
    has_attachment_risk = "RISKY_ATTACHMENT" in value.reason_codes and bool(attachment_allowed)
    if value.classification == "PHISHING" and not has_model_risk:
        raise ValueError("UNSUPPORTED_RISK")
    if value.classification == "SUSPICIOUS" and not (has_model_risk or has_attachment_risk):
        raise ValueError("UNSUPPORTED_RISK")


def restore_judgment(value, mapping):
    return JudgmentOutput(
        classification=value.classification,
        reason_codes=value.reason_codes,
        evidence_refs=[mapping[ref] for ref in value.evidence_refs],
        uncertainties=value.uncertainty_codes,
        rationale=value.rationale,
        explanations=[
            RiskExplanation(
                **(
                    item.model_dump()
                    | {"evidence_refs": [mapping[ref] for ref in item.evidence_refs]}
                )
            )
            for item in value.explanations
        ],
    )


def validate_run(mail, rules, model):
    if model.handoff is None or model.structured_judgment is None:
        raise ValueError("MISSING_HANDOFF")
    if model.judgment_format == "core_slots_1":
        actual_coverage = coverage_for_mail(mail)
        if model.coverage.status == "complete" and model.coverage != actual_coverage:
            raise ValueError("MISMATCHED_COVERAGE")
    packet, mapping = project(
        mail,
        rules,
        model.features,
        scope_id=model.handoff.scope_id,
        coverage=model.coverage if model.judgment_format == "core_slots_1" else None,
        native=model.judgment_format == "core_slots_1",
    )
    if packet != model.handoff or mapping != model.handoff_evidence_map:
        raise ValueError("MISMATCHED_HANDOFF")
    value = Judgment.model_validate_json(model.structured_judgment.model_dump_json(), strict=True)
    validate_judgment(value, packet, mapping, simulation=model.is_simulation)
    if model.judgment_format == "core_slots_1":
        from app.analysis.llm.core import validate_core

        if model.decision_core is None:
            raise ValueError("MISSING_CORE")
        rebuilt = validate_core(
            model.decision_core, packet, mapping, simulation=model.is_simulation
        )
        if rebuilt.model_dump(mode="json", exclude={"core"}) != value.model_dump(mode="json"):
            raise ValueError("MISMATCHED_CORE")
    if restore_judgment(value, mapping) != model.judgment:
        raise ValueError("MISMATCHED_JUDGMENT")
    return packet, set(mapping.values())
