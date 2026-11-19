# 檔案功能：整理已驗證的模型特徵、證據與不確定因素，提供可追溯的分析理由。

import re

from app.application.deterministic_report import (
    CoreEvidenceUnavailable,
    base_model,
    build_deterministic_model,
)
from app.application.event_report import SOURCE_NOTE as EVENT_SOURCE_NOTE
from app.application.event_report import build_event_model
from app.domain.email_models import NormalizedEmail
from app.domain.evidence import EvidenceRegistry
from app.domain.llm_models import LLMRun
from app.domain.reliability_models import PresentationState

SOURCE_NOTE = (
    "AI 依擷取後的結構化觀察提出判斷，未直接複核信件原文；引用原文由系統提供，請對照確認。"
)
OBSERVATION_LABELS = {
    "authentication": "寄件驗證資訊",
    "credential_request": "敏感資料要求",
    "urgency_fear": "時間壓力與威脅",
    "impersonation": "身分冒用跡象",
    "generic_salutation": "一般稱謂",
    "url_deception": "網址偽裝跡象",
    "language": "語系與措辭異常",
    "analysis_override": "干預分析的文字",
}
UNCERTAINTY_LABELS = {
    "AMBIGUOUS_REQUEST": "信件要求的用途仍需確認。",
    "AMBIGUOUS_IDENTITY": "寄件人身分仍需確認。",
    "AMBIGUOUS_URL": "連結的用途與導向仍需確認。",
    "UNMAPPED_CONTENT": "部分內容無法由目前的觀察項目充分判讀，請對照原文。",
    "SIMULATION": "這次使用離線模擬。",
}


def explain(email, models, result) -> dict:
    structured = isinstance(models, LLMRun) and models.analysis_method == "structured_dual"
    event_method = isinstance(models, LLMRun) and models.analysis_method == "structured_event_dual"
    output = {
        "reason_source": "deterministic_event_facts"
        if event_method
        else "structured_observations"
        if structured
        else "legacy_unknown",
        "available": False,
        "parser_warnings": email.parse_warnings if isinstance(email, NormalizedEmail) else [],
        "review_items": [
            item.model_dump(mode="json")
            for item in result.review_items
            if item.code != "LLM_UNCERTAINTY"
        ],
        "model": None,
        "presentation": PresentationState(reason_codes=["CORE_NOT_VALID"]).model_dump(mode="json"),
    }
    if (
        not isinstance(email, NormalizedEmail)
        or not isinstance(models, LLMRun)
        or models.is_simulation
        or result.status != "COMPLETED"
    ):
        return output
    registry = EvidenceRegistry(email)
    refs = list(
        dict.fromkeys(
            [ref for item in models.features.features for ref in item.evidence_refs]
            + [ref for item in (models.features.observations or []) for ref in item.evidence_refs]
            + models.features.suspicious_url_refs
            + models.judgment.evidence_refs
            + [ref for item in models.judgment.explanations for ref in item.evidence_refs]
        )
    )
    try:
        if event_method:
            packet = models.event_handoff
            if packet is None or models.event_decision_core is None:
                raise ValueError("CORE_EVIDENCE_UNAVAILABLE")
            sources = {
                item.id: item for item in [*packet.events, *packet.relations, *packet.signals]
            }
            for _, binding in models.event_decision_core.reason_slots:
                if binding is None:
                    continue
                if binding.source_id is not None:
                    source = sources.get(binding.source_id)
                    if source is None or set(binding.evidence_refs) != set(source.evidence_ids):
                        raise ValueError("CORE_EVIDENCE_UNAVAILABLE")
                for reference in binding.evidence_refs:
                    registry.resolve(models.event_evidence_map[reference])
        if models.judgment_format == "core_slots_1":
            by_id = {item.id for item in models.handoff.observations}
            for unit in models.structured_judgment.reason_supports or []:
                if unit.observation_id is not None and unit.observation_id not in by_id:
                    raise ValueError("CORE_EVIDENCE_UNAVAILABLE")
                for reference in unit.evidence_refs:
                    if reference not in models.handoff_evidence_map:
                        raise ValueError("CORE_EVIDENCE_UNAVAILABLE")
                    registry.resolve(models.handoff_evidence_map[reference])
        evidence = [{"ref": ref, "text": registry.resolve(ref)} for ref in refs]
    except (ValueError, KeyError):
        if event_method or models.judgment_format == "core_slots_1":
            raise CoreEvidenceUnavailable("CORE_EVIDENCE_UNAVAILABLE") from None
        return output
    output["available"] = True
    if event_method:
        try:
            output["model"] = build_event_model(models, evidence)
            state = PresentationState(
                source="deterministic_event_facts",
                status="complete",
                evidence_complete=True,
                reason_codes=["TEMPLATE_AVAILABLE"],
            )
        except Exception:
            # Required references resolved above; display fallback never rescues invalid evidence.
            output["model"] = base_model(models, evidence)
            output["model"]["source_note"] = EVENT_SOURCE_NOTE
            state = PresentationState(
                source="deterministic_event_facts",
                status="degraded",
                evidence_complete=True,
                reason_codes=["TEMPLATE_FAILED"],
            )
        output["presentation"] = state.model_dump(mode="json")
        return output
    if models.judgment_format == "core_slots_1":
        output["reason_source"] = "deterministic_observations"
        try:
            output["model"] = build_deterministic_model(
                models, evidence, OBSERVATION_LABELS, UNCERTAINTY_LABELS
            )
            state = PresentationState(
                source="deterministic_observations",
                status="complete",
                evidence_complete=True,
                reason_codes=["TEMPLATE_AVAILABLE"],
            )
        except Exception:
            # Core/registry were already validated. A display failure cannot change the decision.
            output["model"] = base_model(models, evidence)
            state = PresentationState(
                source="deterministic_observations",
                status="degraded",
                evidence_complete=True,
                reason_codes=["TEMPLATE_FAILED"],
            )
        output["presentation"] = state.model_dump(mode="json")
        return output
    output["presentation"] = PresentationState(
        source="legacy_model",
        status="legacy",
        evidence_complete=True,
        reason_codes=["LEGACY_PRESENTATION"],
    ).model_dump(mode="json")
    output["model"] = {
        "source_note": SOURCE_NOTE if structured else "舊式分析未記錄結構化隔離來源，請對照原文。",
        "evidence_refs": models.judgment.evidence_refs,
        "classification": models.judgment.classification.value,
        "reason_codes": models.judgment.reason_codes,
        "rationale": models.judgment.rationale,
        "explanations": [item.model_dump(mode="json") for item in models.judgment.explanations],
        "features": [item.model_dump(mode="json") for item in models.features.features],
        "social_engineering_indicators": models.features.social_engineering_indicators,
        "uncertainties": list(
            dict.fromkeys(models.features.uncertainties + models.judgment.uncertainties)
        ),
        "scope_limitations": list(
            dict.fromkeys(models.features.scope_limitations + models.judgment.scope_limitations)
        ),
        "evidence": evidence,
    }
    if structured:
        model = output["model"]

        # Opaque references remain in diagnostic JSON, never in reader prose.
        def reader_text(value):
            return re.sub(r"\b[ef]_[0-9a-f]{16}_[0-9]{3}\b", "所引原文", value)

        model["rationale"] = reader_text(model["rationale"])
        for item in model["explanations"]:
            item["explanation"] = reader_text(item["explanation"])
        # Human views never substitute model-supplied quotes for registry evidence.
        output["model"]["features"] = [
            dict(
                feature_type=item.kind,
                description=OBSERVATION_LABELS[item.kind]
                + (
                    "：擷取結果發現此訊號。"
                    if item.assessment == "observed"
                    else "：擷取結果仍有疑問。"
                ),
                evidence_refs=item.evidence_refs,
            )
            for item in models.features.observations
            if item.assessment in {"observed", "uncertain"}
        ]
        output["model"]["uncertainties"] = list(
            dict.fromkeys(
                [UNCERTAINTY_LABELS[code] for code in models.judgment.uncertainties]
                + (
                    [UNCERTAINTY_LABELS["UNMAPPED_CONTENT"]]
                    if any(item.assessment == "uncertain" for item in models.features.observations)
                    else []
                )
            )
        )
        output["model"]["scope_limitations"] = ["未連線驗證寄件者簽章、網址信譽或附件內容。"]
    return output
