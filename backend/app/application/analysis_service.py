# 檔案功能：依序執行解析、規則、LangChain 與決策，限制整體耗時並保存公開分析結果。

import asyncio
import hashlib
from datetime import UTC, datetime
from time import perf_counter
from uuid import uuid4

from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.analysis.decision import finalize_analysis
from app.analysis.decision.engine import failed_decision, retain_rule_context
from app.analysis.llm.pipeline import configured_pipeline, failure
from app.analysis.llm.settings import LLMSettings, fake_settings
from app.analysis.parser.async_execution import run_parser_job
from app.analysis.parser.result import parse_file_bytes_result
from app.analysis.rules import RuleEngine
from app.application.deterministic_report import CoreEvidenceUnavailable
from app.application.explanation import explain
from app.application.presentation import present, transient_urls
from app.application.reliability import summarize
from app.application.review_document import review_document
from app.config import AppSettings
from app.domain.enums import EmailSource
from app.domain.llm_models import LLMFailure, LLMRun
from app.domain.stage_failure import StageFailure
from app.domain.versions import API_VERSION
from app.infrastructure.db.repository import HistoryRepository


class AnalysisService:
    def __init__(self, repository: HistoryRepository, settings: AppSettings):
        self.repository, self.settings = repository, settings

    @staticmethod
    def _timing(created_at, started_at, started_clock):
        return {
            "created_at": created_at.isoformat(),
            "started_at": started_at.isoformat(),
            "completed_at": datetime.now(UTC).isoformat(),
            "latency_ms": round((perf_counter() - started_clock) * 1000, 3),
            "latency_scope": "analysis_through_review_excludes_persistence",
        }

    def _payload(
        self, result, email, rules, models, mode, activated, rules_matched, *, validated_core=False
    ):
        result = retain_rule_context(result, email, rules)
        payload = present(result)
        payload["api_version"] = API_VERSION
        try:
            explanation = explain(email, models, result)
        except CoreEvidenceUnavailable:
            validated_core = False
            result = failed_decision(
                "CORE_EVIDENCE_UNAVAILABLE",
                analysis_id=result.analysis_id,
                phase=3,
                versions=models.versions,
            )
            result = retain_rule_context(result, email, rules)
            payload = present(result)
            payload["api_version"] = API_VERSION
            explanation = explain(email, models, result)
        payload["analysis_explanation"] = explanation
        payload["analysis_reliability"] = summarize(
            result, models, explanation["presentation"], validated_core=validated_core
        )
        payload["coverage"] = payload["analysis_reliability"]["coverage"]
        if isinstance(email, StageFailure) and email.resource_diagnostic:
            payload["input_diagnostic"] = email.resource_diagnostic.model_dump(mode="json")
        if (
            isinstance(models, LLMRun)
            and models.analysis_method == "structured_event_dual"
            and models.event_extraction is not None
            and models.event_handoff is not None
            and models.event_decision_core is not None
        ):
            payload["analysis_trace"] = {
                "method": "structured_event_dual",
                "judgment_format": models.judgment_format,
                "extraction_wire": "event_extraction_1",
                "handoff_contract": "event_handoff_1",
                "extraction": models.event_extraction.model_dump(mode="json"),
                "handoff": models.event_handoff.model_dump(mode="json"),
                "evidence_map": models.event_evidence_map,
                "decision_core": models.event_decision_core.model_dump(mode="json"),
                "coverage": models.coverage.model_dump(mode="json"),
            }
        elif getattr(models, "analysis_method", None) == "structured_dual":
            payload["analysis_trace"] = {
                "method": "structured_dual",
                "handoff": models.handoff.model_dump(mode="json"),
                "evidence_map": models.handoff_evidence_map,
                "judgment": models.structured_judgment.model_dump(mode="json"),
                "judgment_format": models.judgment_format,
                "decision_core": models.decision_core.model_dump(mode="json")
                if models.decision_core
                else None,
            }
        payload["rule_signal_summary"] = {
            "email_threat_count": sum(
                item.category == "email_threat" for item in result.rule_findings
            ),
            "prompt_injection_count": sum(
                item.category == "prompt_injection" for item in result.rule_findings
            ),
        }
        completed = (
            activated
            and isinstance(models, LLMRun)
            and not any(
                item.code in {"CORE_EVIDENCE_UNAVAILABLE", "INVALID_DECISION_INPUT"}
                for item in result.errors
            )
        )
        codes = [error["code"] for error in payload["errors"]]
        if mode == "fake" and self.settings.enable_test_simulation:
            codes = ["SIMULATED_ANALYSIS"]
        elif not codes and not activated:
            codes = ["MODEL_NOT_STARTED"]
        elif completed:
            codes = ["MODEL_ANALYSIS_COMPLETED"]
        payload["model_analysis"] = {
            "activated": activated,
            "completed": completed,
            "reason_codes": codes,
            "rules_matched": rules_matched,
            "skipped_by_rules": False,
        }
        # Persist only closed diagnostic codes and fields; no raw provider reply or exception.
        if isinstance(models, LLMFailure) or (
            isinstance(models, LLMRun)
            and any(call.transport_diagnostic is not None for call in models.calls)
        ):
            model_diagnostic = getattr(models, "diagnostic", None)
            payload["model_diagnostics"] = {
                "analysis_method": getattr(models, "analysis_method", None),
                "judgment_format": getattr(models, "judgment_format", None),
                "failed_stage": getattr(models, "failed_stage", None),
                "diagnostic": model_diagnostic.model_dump(mode="json")
                if model_diagnostic
                else None,
                "calls": [
                    {
                        "stage": call.stage,
                        "attempt": call.attempt,
                        "error_code": call.error_code,
                        "latency_ms": call.latency_ms,
                        "timeout_kind": call.timeout_kind,
                        "transport_diagnostic": call.transport_diagnostic.model_dump(mode="json")
                        if call.transport_diagnostic
                        else None,
                        "output_token_parameter": call.output_token_parameter,
                        "request_schema_sha256": call.request_schema_sha256,
                        "request_data_sha256": call.request_data_sha256,
                        "request_prompt_sha256": call.request_prompt_sha256,
                        "request_budget": call.request_budget.model_dump(mode="json")
                        if call.request_budget
                        else None,
                        "usage": call.usage.model_dump(mode="json") if call.usage else None,
                        "diagnostic": call.diagnostic.model_dump(mode="json")
                        if call.diagnostic
                        else None,
                    }
                    for call in models.calls
                ],
            }
        payload["privacy_note"] = (
            "本機另存原始檔文字、解碼正文與覆核證據；另存通過驗證的結構化模型特徵與理由，供人員對照。"
        )
        for item in payload["review_items"]:
            item["message"] = "此項需人工判讀；請對照信件內容與證據定位。"
        return payload

    async def _recover_saved(self, identifier, content_hash):
        try:
            async with asyncio.timeout(self.settings.reconciliation_timeout_seconds):
                saved = await self.repository.get(identifier)
            if saved is None:
                return None, "not_saved"
            document = saved.get("source_document") or {}
            if (
                saved.get("analysis_id") != str(identifier)
                or document.get("content_hash") != content_hash
            ):
                return None, "unconfirmed"
            return saved | {"persistence": {"state": "saved", "reconciled": True}}, "saved"
        except Exception:
            return None, "unconfirmed"

    async def analyze(self, raw: bytes, source: EmailSource, mode: str):
        created_at = datetime.now(UTC)
        started_at, started_clock = datetime.now(UTC), perf_counter()
        timing = None
        identifier = uuid4()
        digest = hashlib.sha256(raw).hexdigest()
        email = rules = models = None
        execution_versions = None
        activated = rules_matched = saving = False
        validated_core = False

        def record_execution(versions):
            nonlocal execution_versions
            execution_versions = versions.model_copy(deep=True)

        try:
            # One budget covers parsing, models, presentation, review and the save transaction.
            async with asyncio.timeout(self.settings.analysis_timeout_seconds):
                email = await run_parser_job(parse_file_bytes_result, raw, source)
                rules = RuleEngine().analyze_result(email)
                rules_matched = bool(getattr(rules, "findings", []))
                if isinstance(rules, StageFailure):
                    models = rules
                else:
                    try:
                        settings = LLMSettings()
                        if mode == "fake" and not self.settings.enable_test_simulation:
                            configured = failure("LLM_TEST_MODE_DISABLED")
                        else:
                            configured = configured_pipeline(
                                fake_settings(settings) if mode == "fake" else settings
                            )
                        activated = mode != "fake" and not isinstance(configured, StageFailure)
                        models = (
                            configured
                            if isinstance(configured, StageFailure)
                            else await configured.analyze_result(
                                email, rules, on_started=record_execution
                            )
                        )
                    except (ValidationError, SettingsError):
                        models = failure("LLM_CONFIGURATION_INVALID")
                result = finalize_analysis(email, rules, models, analysis_id=identifier)
                payload = self._payload(
                    result, email, rules, models, mode, activated, rules_matched
                )
                validated_core = payload["analysis_reliability"]["core_status"] == "valid"
                document = await run_parser_job(review_document, raw, source.value, email, payload)
                timing = self._timing(created_at, started_at, started_clock)
                payload.update(timing)
                payload["persistence"] = {"state": "saved", "reconciled": False}
                saving = True
                await self.repository.save(payload, source.value, digest, document)
                return payload | {
                    "transient_urls": transient_urls(email),
                    "source_document": document,
                }
        except TimeoutError:
            error_code = "ANALYSIS_TIMEOUT"
        except Exception:
            error_code = "ANALYSIS_SERVICE_FAILED"
        persistence = "not_saved"
        if saving:
            saved, persistence = await self._recover_saved(identifier, digest)
            if saved is not None:
                return saved | {"transient_urls": transient_urls(email)}
        result = failed_decision(
            error_code,
            analysis_id=identifier,
            versions=getattr(models, "versions", None) or execution_versions,
        )
        payload = self._payload(
            result,
            email,
            rules,
            models,
            mode,
            activated,
            rules_matched,
            validated_core=validated_core,
        )
        payload["persistence"] = {"state": persistence, "reconciled": False}
        # The budget is exhausted: preserve raw evidence, never start another HTML parser.
        document = review_document(raw, source.value, email, payload, parse_display=False)
        payload.update(timing or self._timing(created_at, started_at, started_clock))
        return payload | {"transient_urls": transient_urls(email), "source_document": document}

    async def preview(self, raw: bytes, source: EmailSource):
        async with asyncio.timeout(8):
            email = await run_parser_job(parse_file_bytes_result, raw, source)
            rules = RuleEngine().analyze_result(email)
            document = await run_parser_job(review_document, raw, source.value, email, {})
        if isinstance(rules, StageFailure):
            return rules.model_dump(mode="json") | {
                "preliminary": True,
                "source_document": document,
            }
        return dict(
            source_document=document,
            preliminary=True,
            phase=2,
            final_classification=None,
            findings=[item.model_dump(mode="json") for item in rules.findings],
            review_required=rules.review_required,
            transient_urls=transient_urls(email),
        )
