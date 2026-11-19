# 檔案功能：協調雙模型分析、輸出與證據驗證，以及期限、重試和失敗回報。

import asyncio
import json
from collections.abc import Callable
from time import perf_counter

from langsmith import tracing_context
from pydantic import ValidationError

from app.analysis.llm.budget import over_budget, request_budget
from app.analysis.llm.core import check_schema_subset
from app.analysis.llm.evidence_catalog import evidence_catalog, reference_schema
from app.analysis.llm.prompts import PROMPT_A, PROMPT_B
from app.analysis.llm.recovery import reset_connection, retry_delay
from app.analysis.llm.settings import LLMSettings, fake_settings
from app.analysis.llm.workflow import dual_stage_chain
from app.analysis.rules import RuleEngine
from app.analysis.rules.models import RuleRun
from app.domain.analysis_models import AnalysisVersions
from app.domain.email_models import NormalizedEmail, ReviewItem
from app.domain.event_models import EventSupportError
from app.domain.evidence import EvidenceRegistry
from app.domain.handoff_models import ReasonSupportError
from app.domain.llm_models import (
    CallMetadata,
    FeatureOutput,
    JudgmentOutput,
    LLMFailure,
    LLMRun,
    OutputDiagnostic,
    RecoveryEvent,
    TokenUsage,
    provider_label,
)
from app.domain.stage_failure import StageFailure, stage_failure
from app.domain.versions import (
    LEGACY_PROMPT_A_VERSION,
    LEGACY_PROMPT_B_VERSION,
    LLM_PIPELINE_VERSION,
    LLM_SCHEMA_VERSION,
    PARSER_VERSION,
    RULESET_VERSION,
)
from app.infrastructure.llm_provider.base import (
    GenerationRequest,
    LLMProvider,
    ProviderResponse,
)
from app.infrastructure.llm_provider.errors import (
    output_diagnostic,
    provider_usage,
    recovery_policy,
)
from app.infrastructure.llm_provider.fake import FakeProvider
from app.infrastructure.llm_provider.openai import OpenAIProvider


class LLMError(Exception):
    def __init__(self, code: str, *, failover_allowed=False, diagnostic=None):
        self.code = code
        self.failover_allowed = failover_allowed
        self.diagnostic = diagnostic
        super().__init__(code)


def evidence_error(exc):
    known = {
        "UNSUPPORTED_UNCERTAINTY",
        "INVALID_SIMULATION_CLAIM",
        "INVALID_OBSERVATION",
        "INVALID_EVIDENCE",
        "UNSUPPORTED_REASON",
        "CONTRADICTORY_REASON",
        "UNSUPPORTED_SAFE",
        "UNSUPPORTED_RISK",
        "INSUFFICIENT_SUPPORT",
        "INVALID_OBSERVATION_REFERENCE",
        "INCONSISTENT_REASON_SUPPORT",
        "INVALID_APPLICABILITY",
        "INVALID_RULE_CONTEXT",
        "INVALID_EVIDENCE_REFERENCE",
        "INCOMPLETE_COVERAGE",
        "INVALID_EVENT_REFERENCE",
        "INVALID_EXTRACTION_STATE",
        "UNSUPPORTED_EVENT_REASON",
        "INCOMPLETE_SEMANTICS",
        "EVENT_LIMIT_EXCEEDED",
    }
    constraint = (
        exc.args[0].lower()
        if len(exc.args) == 1 and isinstance(exc.args[0], str) and exc.args[0] in known
        else None
    )
    return LLMError(
        "LLM_EVIDENCE_INVALID",
        diagnostic=OutputDiagnostic(
            reason="insufficient_support"
            if constraint == "insufficient_support"
            else "evidence_mismatch",
            constraint=constraint,
            support_violations=exc.violations if isinstance(exc, ReasonSupportError) else [],
            event_support_violations=exc.violations if isinstance(exc, EventSupportError) else [],
            category="core_support",
        ),
    )


def failure(
    code: str,
    failed_stage="configuration",
    *,
    versions=None,
    calls=None,
    recovery_events=None,
    diagnostic=None,
    coverage=None,
    event_extraction_status=None,
    event_semantic_completeness=None,
    event_count=None,
    relation_count=None,
    analysis_method=None,
    judgment_format=None,
) -> LLMFailure:
    return LLMFailure(
        **stage_failure(3, code).model_dump(),
        failed_stage=failed_stage,
        versions=versions,
        calls=calls or [],
        recovery_events=recovery_events or [],
        diagnostic=diagnostic,
        coverage=coverage or {},
        event_extraction_status=event_extraction_status,
        event_semantic_completeness=event_semantic_completeness,
        event_count=event_count,
        relation_count=relation_count,
        analysis_method=analysis_method,
        judgment_format=judgment_format,
    )


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise LLMError(
                "LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="duplicate_json_key")
            )
        result[key] = value
    return result


def _reject_constant(value):
    raise LLMError("LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="non_finite_json"))


def decode_output(raw: str, schema: type[FeatureOutput | JudgmentOutput], limit: int):
    try:
        if not isinstance(raw, str):
            raise LLMError(
                "LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="invalid_response")
            )
        if len(raw.encode("utf-8")) > limit:
            raise LLMError(
                "LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="output_byte_limit")
            )
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        return schema.model_validate_json(json.dumps(value), strict=True)
    except ValidationError as exc:
        # Dynamic extra keys, supplied values and validator messages may contain mail.
        fields = sorted(
            {
                str(error["loc"][0])
                for error in exc.errors(
                    include_input=False, include_context=False, include_url=False
                )
                if error["loc"] and error["loc"][0] in schema.model_fields
            }
        )
        from typing import get_args

        from app.domain.event_models import EventReason
        from app.domain.handoff_models import Reason

        allowed_parts = {
            "decision",
            "classification",
            "reason_slots",
            "reason_supports",
            "observation_id",
            "evidence_refs",
            "reason_code",
            "uncertainty_codes",
            "rationale",
            "explanations",
            "assessment",
            "explanation",
            "category",
            "observations",
            "kind",
            "features",
            "description",
            "feature_type",
            *get_args(Reason),
            *get_args(EventReason),
            "contract",
            "status",
            "events",
            "relations",
            "inspected_refs",
            "action",
            "target",
            "actor",
            "recipient",
            "channel",
            "deadline",
            "consequence",
            "context",
            "polarity",
            "secret_kind",
            "local_id",
            "source_event",
            "target_event",
            "source_id",
        }
        paths = []
        for error in exc.errors(include_input=False, include_context=False, include_url=False):
            parts = []
            for part in error["loc"]:
                if len(parts) == 4:
                    break
                if isinstance(part, int):
                    parts.append("$item")
                elif part in allowed_parts:
                    parts.append(part)
                else:
                    break
            if parts and ".".join(parts) not in paths and len(paths) < 20:
                paths.append(".".join(parts))
        known_constraints = {
            "INCOMPLETE_OBSERVATIONS",
            "OBSERVATION_REQUIRES_REFERENCE",
            "INVALID_APPLICABILITY",
            "OBSERVATION_REQUIRES_EVIDENCE",
            "NON_UNKNOWN_REQUIRES_EVIDENCE_AND_REASON",
            "UNKNOWN_REQUIRES_REASON",
            "INVALID_EVENT_REFERENCE",
            "INVALID_EXTRACTION_STATE",
        }
        constraint = None
        for error in exc.errors(include_input=False, include_url=False):
            cause = error.get("ctx", {}).get("error")
            if (
                isinstance(cause, ValueError)
                and len(cause.args) == 1
                and isinstance(cause.args[0], str)
                and cause.args[0] in known_constraints
            ):
                constraint = cause.args[0].lower()
                break
        raise LLMError(
            "LLM_OUTPUT_INVALID",
            diagnostic=OutputDiagnostic(
                reason="schema_mismatch",
                field_paths=paths,
                fields=fields,
                constraint=constraint,
                category="presentation"
                if any(field in {"rationale", "explanations"} for field in fields)
                or constraint == "observation_requires_evidence"
                else "core_schema",
            ),
        ) from None
    except (ValueError, TypeError, RecursionError):
        raise LLMError(
            "LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="invalid_json")
        ) from None


def feature_refs(output: FeatureOutput) -> list[str]:
    return (
        [ref for item in output.features for ref in item.evidence_refs]
        + list(output.suspicious_url_refs)
        + [ref for item in (output.observations or []) for ref in item.evidence_refs]
    )


class DualLLMPipeline:
    # Explicit comparison implementation; product entry points use the isolated subclass.
    version = LLM_PIPELINE_VERSION
    analysis_method = "legacy_dual"
    prompt_a_version = LEGACY_PROMPT_A_VERSION
    prompt_b_version = LEGACY_PROMPT_B_VERSION

    def _output_schema(self, stage):
        return FeatureOutput if stage == "a" else JudgmentOutput

    def _system_prompt(self, stage):
        return PROMPT_A if stage == "a" else PROMPT_B

    def _model_uncertainties(self, features, judgment):
        return [*features.uncertainties, *judgment.uncertainties]

    def _run_fields(self, state):
        return {"analysis_method": self.analysis_method}

    def _failure_fields(self, state):
        return {}

    def __init__(
        self,
        provider_a: LLMProvider,
        provider_b: LLMProvider | None = None,
        *,
        settings: LLMSettings,
        provider_name: str = "custom",
        simulation: bool = False,
    ):
        if not settings.model_a.strip() or not settings.model_b.strip():
            raise ValueError("LLM_NOT_CONFIGURED")
        self.provider_a = provider_a
        self.provider_b = provider_b if provider_b is not None else provider_a
        self.settings = settings
        self.simulation = (
            simulation
            or isinstance(provider_a, FakeProvider)
            or isinstance(self.provider_b, FakeProvider)
        )
        self.provider_name = (
            "fake"
            if isinstance(provider_a, FakeProvider) or isinstance(self.provider_b, FakeProvider)
            else provider_label(provider_name)
        )
        self.workflow = dual_stage_chain(self._extract_features, self._judge_risk)
        self.endpoint_pools = None

    async def analyze_result(
        self,
        email: NormalizedEmail | StageFailure,
        rules: RuleRun | StageFailure,
        *,
        on_started: Callable[[AnalysisVersions], None] | None = None,
    ) -> LLMRun | StageFailure:
        # Upstream failures retain the original phase; never call either model.
        if isinstance(email, StageFailure):
            return email
        if isinstance(rules, StageFailure):
            return rules
        try:
            mail, run = self._validate_input(email, rules)
        except (ValueError, TypeError, AttributeError):
            return failure("INVALID_LLM_INPUT", "input", **self._failure_fields({}))
        versions = AnalysisVersions(
            llm_pipeline=LLM_PIPELINE_VERSION,
            llm_schema=LLM_SCHEMA_VERSION,
            parser=mail.parser_version,
            ruleset=run.ruleset_version,
            prompt_a=self.prompt_a_version,
            prompt_b=self.prompt_b_version,
            model_a=self.settings.model_a,
            model_b=self.settings.model_b,
        )
        if on_started is not None:
            on_started(versions.model_copy(deep=True))
        calls: list[CallMetadata] = []
        events: list[RecoveryEvent] = []
        deadline = asyncio.get_running_loop().time() + self.settings.total_timeout_seconds
        state = dict(
            mail=mail,
            run=run,
            registry=EvidenceRegistry(mail),
            calls=calls,
            events=events,
            deadline=deadline,
            stage="a",
            versions=versions,
            on_started=on_started,
        )
        try:
            async with asyncio.timeout_at(deadline):
                with tracing_context(enabled=False):
                    state = await self.workflow.ainvoke(
                        state, config={"callbacks": [], "recursion_limit": 8}
                    )
                features, judgment = state["features"], state["judgment"]
            reviews = [item.model_copy(deep=True) for item in run.review_items]
            reviews.extend(state.get("run_reviews", []))
            for uncertainty in self._model_uncertainties(features, judgment):
                reviews.append(ReviewItem(code="LLM_UNCERTAINTY", message=uncertainty))
            if self.simulation:
                reviews.append(
                    ReviewItem(
                        code="FAKE_PROVIDER",
                        message="離線模擬輸出，尚無真實模型分析，不得當成最終分類。",
                    )
                )
            return LLMRun(
                **self._run_fields(state),
                provider=self.provider_name,
                simulation=self.simulation,
                versions=versions,
                content_hash=mail.content_hash,
                rules=run,
                features=features,
                judgment=judgment,
                calls=calls,
                recovery_events=events,
                review_items=reviews,
            )
        except TimeoutError:
            for event in events:
                if event.retry_status == "cancelled" or event.connection_reset == "cancelled":
                    event.retry_status = "deadline_exceeded"
            return failure(
                "LLM_TIMEOUT",
                state["stage"],
                versions=versions,
                calls=calls,
                recovery_events=events,
                coverage=state.get("coverage"),
                **self._failure_fields(state),
            )
        except LLMError as exc:
            return failure(
                exc.code,
                state["stage"],
                versions=versions,
                calls=calls,
                recovery_events=events,
                diagnostic=exc.diagnostic,
                coverage=state.get("coverage"),
                **self._failure_fields(state),
            )

    async def _extract_features(self, state):
        state["stage"] = "a"
        mail, run = state["mail"], state["run"]
        payload = {
            "email": mail.model_dump(
                mode="json",
                include={
                    "body_text",
                    "subject",
                    "sender",
                    "reply_to",
                    "headers",
                    "urls",
                    "attachments_metadata",
                    "hidden_texts",
                    "auth_results",
                    "parse_warnings",
                    "review_items",
                },
            ),
            "rules": run.model_dump(mode="json"),
            "evidence_catalog": evidence_catalog(mail),
        }
        state["features"] = await self._call(
            "a",
            payload,
            state["registry"],
            state["calls"],
            state["events"],
            state["deadline"],
            versions=state["versions"],
            on_started=state["on_started"],
        )
        return state

    async def _judge_risk(self, state):
        state["stage"] = "b"
        features, run, registry = state["features"], state["run"], state["registry"]
        refs = list(
            dict.fromkeys(
                feature_refs(features)
                + [ref for item in [*run.findings, *run.review_items] for ref in item.evidence_refs]
            )
        )
        refs = list(dict.fromkeys([*refs, *evidence_catalog(state["mail"])]))
        payload = {
            "source": state["mail"].source.value,
            "authentication_verification": "not_verified",
            "validated_features": features.model_dump(mode="json", exclude_none=True),
            "rules": run.model_dump(mode="json"),
            "parse_warnings": state["mail"].parse_warnings,
            "evidence": {ref: registry.resolve(ref) for ref in refs},
        }
        state["judgment"] = await self._call(
            "b",
            payload,
            registry,
            state["calls"],
            state["events"],
            state["deadline"],
            set(refs),
            versions=state["versions"],
            on_started=state["on_started"],
        )
        return state

    @staticmethod
    def _validate_input(email, rules):
        if not isinstance(email, NormalizedEmail) or not isinstance(rules, RuleRun):
            raise ValueError("INVALID_INPUT")
        mail = NormalizedEmail.model_validate(email.model_dump(exclude_computed_fields=True))
        run = RuleRun.model_validate(rules.model_dump(exclude_computed_fields=True))
        if (
            mail.content_hash != run.content_hash
            or mail.parser_version != run.parser_version
            or mail.parser_version != PARSER_VERSION
            or run.ruleset_version != RULESET_VERSION
        ):
            raise ValueError("MISMATCHED_INPUT")
        registry = EvidenceRegistry(mail)
        known = RuleEngine().rule_versions
        if any(known.get(key) != version for key, version in run.rule_versions.items()):
            raise ValueError("INVALID_RULE_VERSION")
        for item in run.findings:
            if (
                not item.evidence_refs
                or item.is_confirmed_malicious
                or run.rule_versions.get(item.rule_id) != item.rule_version
            ):
                raise ValueError("INVALID_FINDING")
            registry.validate(item.evidence_refs)
        for item in [*mail.review_items, *run.review_items]:
            registry.validate(item.evidence_refs)
        if any(item not in run.review_items for item in mail.review_items):
            raise ValueError("DROPPED_REVIEW")
        return mail, run

    def _request_schema(self, stage, payload, references):
        return reference_schema(self._output_schema(stage).model_json_schema(), references)

    def _validate_output(self, stage, output, payload):
        pass

    def _decode_output(self, stage, raw):
        return decode_output(raw, self._output_schema(stage), self.settings.max_output_bytes)

    def _output_references(self, stage, output):
        """Return references for this wire without coercing a different contract."""
        return (
            feature_refs(output)
            if stage == "a"
            else output.evidence_refs
            + [ref for item in output.explanations for ref in item.evidence_refs]
        )

    def _validate_reference_types(self, stage, output):
        if stage == "a" and any(not ref.startswith("url:") for ref in output.suspicious_url_refs):
            raise ValueError("NOT_URL")

    async def _call(
        self,
        stage,
        payload,
        registry,
        calls,
        events,
        deadline,
        allowed_refs=None,
        *,
        versions=None,
        on_started=None,
    ):
        provider = self.provider_a if stage == "a" else self.provider_b
        candidates = self.endpoint_pools[stage] if self.endpoint_pools else [provider]
        now = asyncio.get_running_loop().time()
        # A pool cannot spend the whole analysis budget on its first dead endpoint.
        # Reserve half the remaining budget for B when A has alternatives.
        stage_deadline = (
            now + (deadline - now) / 2 if stage == "a" and len(candidates) > 1 else deadline
        )
        for index, candidate in enumerate(candidates, 1):
            if asyncio.get_running_loop().time() >= deadline:
                raise LLMError("LLM_TIMEOUT")
            model_id = (
                getattr(candidate, "settings", self.settings).model_a
                if stage == "a"
                else getattr(candidate, "settings", self.settings).model_b
            )
            if versions is not None:
                changed = getattr(versions, "model_" + stage) != model_id
                setattr(versions, "model_" + stage, model_id)
                if on_started is not None and changed:
                    on_started(versions.model_copy(deep=True))
            offset = sum(call.stage == stage for call in calls)
            try:
                remaining = stage_deadline - asyncio.get_running_loop().time()
                endpoint_deadline = asyncio.get_running_loop().time() + remaining / (
                    len(candidates) - index + 1
                )
                async with asyncio.timeout_at(endpoint_deadline):
                    return await self._call_endpoint(
                        stage,
                        payload,
                        registry,
                        calls,
                        events,
                        deadline,
                        allowed_refs,
                        provider=candidate,
                        model_id=model_id,
                        endpoint_index=index,
                        offset=offset,
                    )
            except TimeoutError:
                if asyncio.get_running_loop().time() >= deadline:
                    raise LLMError("LLM_TIMEOUT") from None
                if index == len(candidates):
                    raise LLMError("LLM_ENDPOINTS_OFFLINE") from None
            except LLMError as exc:
                if not self.endpoint_pools or not exc.failover_allowed:
                    raise
                if index == len(candidates):
                    if exc.code == "LLM_RETRY_DELAY_LIMIT":
                        raise
                    raise LLMError("LLM_ENDPOINTS_OFFLINE") from None
        raise AssertionError("UNREACHABLE")

    async def _call_endpoint(
        self,
        stage,
        payload,
        registry,
        calls,
        events,
        deadline,
        allowed_refs=None,
        *,
        provider,
        model_id,
        endpoint_index,
        offset,
    ):
        settings = self.settings
        try:
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False)
        except (ValueError, UnicodeError, RecursionError):
            raise LLMError("INVALID_LLM_INPUT") from None
        request = GenerationRequest(
            system_prompt=self._system_prompt(stage),
            data_json=data,
            response_schema_json=json.dumps(
                self._request_schema(
                    stage,
                    payload,
                    allowed_refs
                    if allowed_refs is not None
                    else payload.get("evidence_catalog", {}),
                )
            ),
            model_id=model_id,
            max_output_tokens=settings.max_output_tokens,
        )
        try:
            check_schema_subset(json.loads(request.response_schema_json))
        except ValueError:
            raise LLMError(
                "LLM_SCHEMA_UNSUPPORTED",
                diagnostic=OutputDiagnostic(reason="schema_mismatch", category="core_schema"),
            ) from None
        budget = request_budget(request, settings, payload)
        if over_budget(budget):
            raise LLMError(
                "LLM_INPUT_TOO_LARGE",
                diagnostic=OutputDiagnostic(
                    reason="input_budget_exceeded",
                    category="input_budget",
                    request_budget=budget,
                    constraint="data_bytes_exceeded"
                    if budget.data_bytes > budget.data_byte_limit
                    else "request_bytes_exceeded"
                    if budget.total_bytes > budget.byte_limit
                    else "estimated_context_exceeded",
                ),
            )
        for attempt in range(1, settings.max_attempts + 1):
            if asyncio.get_running_loop().time() >= deadline:
                if events and events[-1].retry_status == "waiting":
                    events[-1].retry_status = "deadline_exceeded"
                raise LLMError("LLM_TIMEOUT")
            if (
                events
                and events[-1].stage == stage
                and events[-1].after_attempt == offset + attempt - 1
                and events[-1].retry_status == "waiting"
            ):
                events[-1].retry_status = "started"
            start = perf_counter()
            usage = None
            code = None
            policy = None
            diagnostic = None
            try:
                async with asyncio.timeout(settings.call_timeout_seconds):
                    response = await provider.generate_structured(request=request)
                if asyncio.get_running_loop().time() >= deadline:
                    raise LLMError("LLM_TIMEOUT")
                if perf_counter() - start >= settings.call_timeout_seconds:
                    raise TimeoutError
                if not isinstance(response, ProviderResponse):
                    raise LLMError(
                        "LLM_OUTPUT_INVALID", diagnostic=OutputDiagnostic(reason="invalid_response")
                    )
                if response.usage is not None:
                    if not isinstance(response.usage, TokenUsage):
                        raise LLMError(
                            "LLM_OUTPUT_INVALID",
                            diagnostic=OutputDiagnostic(reason="invalid_usage"),
                        )
                    usage = TokenUsage.model_validate(response.usage.model_dump(), strict=True)
                    if usage.output_tokens > settings.max_output_tokens:
                        raise LLMError(
                            "LLM_OUTPUT_INVALID",
                            diagnostic=OutputDiagnostic(reason="output_token_limit"),
                        )
                output = self._decode_output(stage, response.json_text)
                refs = self._output_references(stage, output)
                try:
                    self._validate_output(stage, output, payload)
                    registry.validate(refs)
                    self._validate_reference_types(stage, output)
                    if allowed_refs is not None and not set(refs) <= allowed_refs:
                        raise ValueError("UNSEEN_EVIDENCE")
                except ValueError as exc:
                    raise evidence_error(exc) from None
                # Reject late results even if an adapter incorrectly swallowed cancellation.
                if asyncio.get_running_loop().time() >= deadline:
                    raise LLMError("LLM_TIMEOUT")
                if perf_counter() - start >= settings.call_timeout_seconds:
                    raise TimeoutError
                return output
            except asyncio.CancelledError:
                # External cancellation propagates; total deadline is converted by the caller.
                code = "LLM_TIMEOUT"
                raise
            except LLMError as exc:
                code = exc.code
                diagnostic = exc.diagnostic
            except ValidationError:
                code = "LLM_OUTPUT_INVALID"
                diagnostic = OutputDiagnostic(reason="invalid_usage")
            except Exception as exc:
                # Never serialize raw provider exceptions, headers, prompts, or secrets.
                policy = recovery_policy(exc)
                code = policy.code
                diagnostic = output_diagnostic(exc)
                if diagnostic is not None and diagnostic.category is None:
                    diagnostic.category = (
                        "output_truncated"
                        if diagnostic.reason == "output_truncated"
                        else "core_schema"
                    )
                    diagnostic.finish_reason = (
                        "length" if diagnostic.reason == "output_truncated" else "other"
                    )
                supplied_usage = provider_usage(exc)
                if isinstance(supplied_usage, TokenUsage):
                    usage = supplied_usage
            finally:
                calls.append(
                    CallMetadata(
                        stage=stage,
                        attempt=offset + attempt,
                        endpoint_index=endpoint_index,
                        endpoint_attempt=attempt,
                        model_id=model_id,
                        provider=getattr(getattr(provider, "settings", None), "provider", None),
                        latency_ms=round((perf_counter() - start) * 1000, 3),
                        usage=usage,
                        error_code=code,
                        diagnostic=diagnostic,
                        request_budget=budget,
                    )
                )
            if policy is None or not policy.retryable:
                raise LLMError(code, diagnostic=diagnostic)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                raise LLMError("LLM_TIMEOUT")
            event = RecoveryEvent(stage=stage, after_attempt=offset + attempt, trigger_code=code)
            events.append(event)
            # Discard broken sessions even on the final failed attempt. The provider's
            # next generate_structured must establish a new transport, never reuse this one.
            reset_ok = True
            if policy.reset_connection:
                reset_ok = await reset_connection(
                    provider, event, min(settings.connection_reset_timeout_seconds, remaining)
                )
            if asyncio.get_running_loop().time() >= deadline:
                event.retry_status = "deadline_exceeded"
                raise LLMError("LLM_TIMEOUT")
            if not reset_ok:
                raise LLMError("LLM_RECONNECT_FAILED", failover_allowed=True)
            if attempt == settings.max_attempts:
                raise LLMError(code, failover_allowed=True)
            delay = retry_delay(settings, attempt, policy.retry_after_seconds)
            if delay is None:
                event.retry_status = "delay_limit"
                # 不縮短此端點要求的等待；外層可改用下一個端點，沒有備援時保留原錯誤。
                raise LLMError("LLM_RETRY_DELAY_LIMIT", failover_allowed=True)
            event.retry_delay_seconds = delay
            if delay >= deadline - asyncio.get_running_loop().time():
                event.retry_status = "deadline_exceeded"
                raise LLMError("LLM_TIMEOUT")
            event.retry_status = "waiting"
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                event.retry_status = "cancelled"
                raise
        raise AssertionError("UNREACHABLE")


def configured_pipeline(settings: LLMSettings) -> DualLLMPipeline | LLMFailure:
    from app.analysis.llm.connection import ConnectionConfigurationError, endpoint_pools
    from app.analysis.llm.isolated_pipeline import IsolatedDualLLMPipeline

    if settings.provider.strip() == "fake":
        if not settings._test_simulation:
            return failure("LLM_TEST_MODE_DISABLED")
        return IsolatedDualLLMPipeline(
            FakeProvider(), settings=fake_settings(settings), provider_name="fake"
        )
    try:
        pools = endpoint_pools(settings)
    except ConnectionConfigurationError as exc:
        return failure(exc.code)
    selected = settings.model_copy(
        update={
            "model_a": pools["a"][0].model_a,
            "model_b": pools["b"][0].model_b,
        }
    )
    providers = {
        stage: [OpenAIProvider(item) for item in entries] for stage, entries in pools.items()
    }
    pipeline = IsolatedDualLLMPipeline(
        providers["a"][0],
        providers["b"][0],
        settings=selected,
        provider_name=pools["a"][0].provider,
    )
    pipeline.endpoint_pools = providers
    return pipeline
