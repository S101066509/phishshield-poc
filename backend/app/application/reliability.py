# 檔案功能：分別記錄核心、展示、預算、輸入政策與有效棄權，不以保存成功取代分析完成。
from app.domain.llm_models import LLMFailure, LLMRun
from app.domain.reliability_models import (
    AttemptBudget,
    ReliabilitySummary,
    SemanticExtractionState,
)


def summarize(result, models, presentation, *, validated_core=False):
    valid = isinstance(models, LLMRun) and (result.status == "COMPLETED" or validated_core)
    category = "completed" if result.status == "COMPLETED" else "transport"
    if result.status == "COMPLETED" and result.final_classification == "UNKNOWN":
        category = "valid_unknown"
    if result.status != "COMPLETED":
        code = result.errors[0].code if result.errors else ""
        diagnostic = getattr(models, "diagnostic", None)
        if diagnostic and diagnostic.category:
            category = diagnostic.category
        elif diagnostic and diagnostic.reason == "output_truncated":
            category = "output_truncated"
        elif code == "LLM_EVIDENCE_INVALID" or code in {
            "INVALID_DECISION_INPUT",
            "CORE_EVIDENCE_UNAVAILABLE",
        }:
            category = "core_support"
        elif code == "LLM_OUTPUT_INVALID":
            category = "core_schema"
        elif code == "LLM_INPUT_TOO_LARGE":
            category = "input_budget"
        elif getattr(result, "failed_phase", None) in {1, 2}:
            category = "input_policy"
    calls = getattr(models, "calls", [])
    first_calls = [
        next((call for call in calls if call.stage == stage), None) for stage in ("a", "b")
    ]
    first = (
        "completed"
        if valid and all(call and not call.error_code for call in first_calls)
        else "failed"
        if calls
        else "not_started"
    )
    not_started = not calls and not valid
    return ReliabilitySummary(
        availability="recorded",
        category=category,
        core_status="valid"
        if valid
        else "not_started"
        if not_started
        else "invalid"
        if isinstance(models, (LLMFailure, LLMRun))
        else "not_started",
        presentation=presentation,
        coverage=getattr(models, "coverage", {}),
        semantic_extraction=SemanticExtractionState(
            availability="recorded",
            claimed_status=models.event_extraction.status,
            semantic_completeness=models.event_handoff.semantic_completeness,
            event_count=len(models.event_extraction.events),
            relation_count=len(models.event_extraction.relations),
        )
        if valid and getattr(models, "analysis_method", None) == "structured_event_dual"
        else SemanticExtractionState(
            availability="recorded",
            claimed_status=models.event_extraction_status,
            semantic_completeness=models.event_semantic_completeness,
            event_count=models.event_count,
            relation_count=models.relation_count,
        )
        if isinstance(models, LLMFailure) and getattr(models, "event_extraction_status", None)
        else SemanticExtractionState(),
        first_pass=first,
        attempts=[
            AttemptBudget(
                stage=call.stage,
                attempt=call.attempt,
                completed=call.error_code is None,
                budget=call.request_budget,
                usage=call.usage.model_dump() if call.usage else None,
            )
            for call in calls
        ],
    ).model_dump(mode="json")
