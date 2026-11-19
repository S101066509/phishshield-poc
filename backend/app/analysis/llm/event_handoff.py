# 檔案功能：嚴格驗證語意事件、重算程式訊號、核發封閉交接及逐項驗證分類支持。
"""Trusted projection never forwards mail values or model-authored strings to B."""

import ipaddress
from copy import deepcopy
from uuid import uuid4

from app.analysis.llm.compact_input import coverage_for_mail
from app.analysis.llm.evidence_catalog import evidence_catalog
from app.analysis.rules import RuleEngine
from app.analysis.rules.threat_rules import usable_urls
from app.domain.email_models import ReviewItem
from app.domain.event_models import (
    MAX_EVENTS,
    MAX_RELATIONS,
    MAX_SIGNALS,
    EventAttributes,
    EventCoreResponse,
    EventDecisionCore,
    EventExtraction,
    EventHandoff,
    EventReasonSlots,
    EventSupportError,
    EventSupportViolation,
    ProgramSignal,
    ProjectedEvent,
    ProjectedRelation,
)
from app.domain.evidence import EvidenceRegistry

REASON_CODES = tuple(EventReasonSlots.model_fields)
RISK_CODES = frozenset(REASON_CODES) - {
    "NO_RISK_FACTS",
    "EVIDENCE_INSUFFICIENT",
    "SIMULATED_ANALYSIS",
}
STRONG_CODES = frozenset(
    {"SECRET_DISCLOSURE_REQUEST", "COERCIVE_ACTION_REQUEST", "LINKED_EXECUTION_REQUEST"}
)
# These map only the registered pattern identity, never a rule's free summary.
RULE_SIGNAL_KINDS = {
    "EMAIL_REPLY_TO_DOMAIN_MISMATCH": "sender_reply_mismatch",
    "EMAIL_URL_DISPLAY_MISMATCH": "url_display_mismatch",
    "EMAIL_SHORT_URL": "short_url",
    "EMAIL_REDIRECT_PARAMETER": "redirect_parameter",
    "EMAIL_CREDENTIAL_REQUEST": "credential_pattern",
    "EMAIL_URGENCY": "urgency_pattern",
    "EMAIL_ATTACHMENT_EXTENSION": "attachment_extension",
    **{
        key: "analysis_manipulation"
        for key in RuleEngine().rule_versions
        if key.startswith("INJECTION_")
    },
}
ATTRIBUTE_FIELDS = tuple(EventAttributes.model_fields)


def validate_event_extraction(value, registry):
    """Only current, actually supplied catalog references are eligible for A."""
    value = EventExtraction.model_validate_json(value.model_dump_json(), strict=True)
    supplied = (
        set(registry)
        if not isinstance(registry, EvidenceRegistry)
        else set(evidence_catalog(registry.email))
    )
    if not set(value.evidence_refs) <= supplied:
        raise ValueError("INVALID_EVIDENCE_REFERENCE")
    return value


def extraction_schema(registry):
    references = (
        sorted(registry)
        if not isinstance(registry, EvidenceRegistry)
        else sorted(evidence_catalog(registry.email))
    )
    schema = EventExtraction.model_json_schema()
    schema.setdefault("$defs", {})["ProvidedEventReference"] = {
        "type": "string",
        "enum": references,
    }

    def bind(node):
        if isinstance(node, dict):
            for name, field in node.get("properties", {}).items():
                if name in {"evidence_refs", "inspected_refs"}:
                    field["items"] = {"$ref": "#/$defs/ProvidedEventReference"}
            for child in node.values():
                bind(child)
        elif isinstance(node, list):
            for child in node:
                bind(child)

    bind(schema)
    return schema


def _key(event):
    return tuple(getattr(event, field) for field in ATTRIBUTE_FIELDS) + (
        tuple(sorted(set(event.evidence_refs))),
    )


def _program_signals(mail, rules):
    engine = RuleEngine(enabled_ids=rules.rule_versions)
    if engine.analyze(mail) != rules:
        raise ValueError("INVALID_RULE_CONTEXT")
    grouped = {}
    for finding in rules.findings:
        kind = RULE_SIGNAL_KINDS.get(finding.rule_id)
        if kind is None:
            raise ValueError("INVALID_RULE_CONTEXT")
        grouped.setdefault(kind, set()).update(finding.evidence_refs)
    for index, url in usable_urls(mail):
        authority = url.normalized_url.split("://", 1)[-1].split("/", 1)[0]
        if "@" in authority:
            grouped.setdefault("url_userinfo", set()).add(f"url:{index}")
        try:
            ipaddress.ip_address(url.hostname or "")
        except ValueError:
            pass
        else:
            grouped.setdefault("url_ip_host", set()).add(f"url:{index}")
    output = []
    # Chunk by four without dropping any reference; over-budget rejects the packet.
    for kind, refs in sorted(grouped.items()):
        ordered = sorted(refs)
        output.extend(
            (kind, tuple(ordered[index : index + 4])) for index in range(0, len(ordered), 4)
        )
    if len(output) > MAX_SIGNALS:
        raise ValueError("EVENT_LIMIT_EXCEEDED")
    return output


def _semantic_completeness(extraction):
    if len(extraction.events) == MAX_EVENTS or len(extraction.relations) == MAX_RELATIONS:
        return "limit_reached"
    if extraction.status != "extracted":
        return extraction.status
    if any(event.action == "other" or event.target == "other" for event in extraction.events):
        return "unrepresentable"
    if any(
        event.context == "unclear"
        or event.polarity == "unclear"
        or event.channel == "unclear"
        or event.deadline == "unclear"
        or event.consequence == "unclear"
        for event in extraction.events
    ):
        return "unclear"

    # Preserve both claims. Conflicting polarity over the same supplied evidence blocks SAFE.
    def polarity_key(event):
        return tuple(getattr(event, field) for field in ATTRIBUTE_FIELDS if field != "polarity") + (
            tuple(sorted(set(event.evidence_refs))),
        )

    positive = {polarity_key(event) for event in extraction.events if event.polarity == "affirmed"}
    if any(
        event.polarity == "negated" and polarity_key(event) in positive
        for event in extraction.events
    ):
        return "unclear"
    return "complete"


def project_events(mail, rules, extraction, registry=None, *, scope_id=None, coverage=None):
    catalog = evidence_catalog(mail)
    extraction = validate_event_extraction(extraction, catalog if registry is None else registry)
    if not set(extraction.evidence_refs) <= set(catalog):
        raise ValueError("INVALID_EVIDENCE_REFERENCE")
    signals = _program_signals(mail, rules)
    references = set(extraction.evidence_refs)
    references.update(ref for _, refs in signals for ref in refs)
    EvidenceRegistry(mail).validate(sorted(references))
    if len(references) > 999:
        raise ValueError("EVENT_LIMIT_EXCEEDED")
    actual_coverage = coverage_for_mail(mail)
    coverage = coverage or actual_coverage
    # compact_mail_1 is lossless. Counts must describe the actual delivered catalog,
    # including a claimed downgrade. A future lossy view needs a verifiable manifest.
    if coverage != actual_coverage:
        raise ValueError("INCOMPLETE_COVERAGE")
    scope_id = scope_id or uuid4().hex[:16]
    forward = {ref: f"e_{scope_id}_{index:03d}" for index, ref in enumerate(sorted(references), 1)}
    unique = {_key(event): event for event in extraction.events}
    event_keys = sorted(unique)
    identifiers = {key: f"v_{scope_id}_{index:03d}" for index, key in enumerate(event_keys, 1)}
    local = {event.local_id: identifiers[_key(event)] for event in extraction.events}
    projected_events = tuple(
        ProjectedEvent(
            **{field: getattr(unique[key], field) for field in ATTRIBUTE_FIELDS},
            id=identifiers[key],
            evidence_ids=tuple(forward[ref] for ref in key[-1]),
        )
        for key in event_keys
    )
    relation_keys = sorted(
        {
            (
                local[item.source_event],
                local[item.target_event],
                item.kind,
                tuple(sorted(set(item.evidence_refs))),
            )
            for item in extraction.relations
        }
    )
    if any(source == target for source, target, _, _ in relation_keys):
        # Collapsing duplicate vertices must not erase a meaningful relation.
        raise ValueError("INVALID_EVENT_REFERENCE")
    relations = tuple(
        ProjectedRelation(
            id=f"r_{scope_id}_{index:03d}",
            source_event=source,
            target_event=target,
            kind=kind,
            evidence_ids=tuple(forward[ref] for ref in refs),
        )
        for index, (source, target, kind, refs) in enumerate(relation_keys, 1)
    )
    packet = EventHandoff(
        scope_id=scope_id,
        extraction_status=extraction.status,
        semantic_completeness=_semantic_completeness(extraction),
        events=projected_events,
        relations=relations,
        signals=tuple(
            ProgramSignal(
                id=f"s_{scope_id}_{index:03d}",
                kind=kind,
                evidence_ids=tuple(forward[ref] for ref in refs),
            )
            for index, (kind, refs) in enumerate(signals, 1)
        ),
        inspected_evidence_ids=tuple(
            forward[ref] for ref in sorted(set(extraction.inspected_refs))
        ),
        rules_complete=rules.rule_versions == RuleEngine().rule_versions,
        parser_warning_count=len(mail.parse_warnings),
        review_required=bool(rules.review_items),
        coverage=coverage,
    )
    return packet, {value: key for key, value in forward.items()}


def _direct(event):
    return event.context == "direct_request" and event.polarity == "affirmed"


def _action_target_eligible(event):
    if event.action in {"login", "verify_account", "grant_access"}:
        return event.target == "account"
    if event.action == "provide_secret":
        return event.target == "authentication_secret"
    if event.action in {"execute", "enable_macros", "install"}:
        return event.target in {"software", "document"}
    if event.action in {"pay", "transfer_money"}:
        return event.target == "money"
    return False


def _coercive(event):
    return (
        _direct(event)
        and _action_target_eligible(event)
        and event.deadline in {"immediate", "within_day"}
        and event.consequence
        in {"account_disabled", "financial_loss", "data_loss", "service_interruption"}
    )


def _benign_target(event):
    if event.action in {"login", "verify_account", "grant_access", "change_password"}:
        return event.target == "account"
    if event.action == "provide_secret":
        return event.target == "authentication_secret" and event.secret_kind != "not_applicable"
    if event.action == "view_document":
        return event.target == "document"
    if event.action in {"download", "execute", "enable_macros", "install"}:
        return event.target in {"software", "document"}
    if event.action in {"pay", "transfer_money"}:
        return event.target == "money"
    if event.action == "call_back":
        return event.target in {"unspecified", "account"}
    return False


def _benign(event):
    # Closed target consistency is necessary even for a claimed notification or denial.
    if not _benign_target(event):
        return False
    if event.context == "unclear" or event.polarity == "unclear":
        return False
    if event.deadline != "none" or event.consequence != "none":
        return False
    if event.polarity == "negated":
        return True
    if event.context in {"reported", "quoted_example", "security_education", "notification"}:
        return True
    return event.action in {"view_document", "call_back"} and event.actor != "unspecified"


def safe_eligible(packet):
    return (
        packet.extraction_status == "extracted"
        and packet.semantic_completeness == "complete"
        and bool(packet.events)
        and all(_benign(event) for event in packet.events)
        and packet.coverage.status == "complete"
        and packet.rules_complete
        and not packet.signals
        and not packet.review_required
        and not packet.parser_warning_count
        # Education/quotation alone supplies no positive assurance about the whole message.
        and any(event.context in {"notification", "direct_request"} for event in packet.events)
    )


def support_options(packet, *, simulation=False):
    """One qualification registry drives generation, runtime, Decision and reports."""
    options = {code: [] for code in REASON_CODES}

    def add(code, item):
        options[code].append({"source_id": item.id, "evidence_refs": list(item.evidence_ids)})

    for event in packet.events:
        if _direct(event):
            if (
                event.action in {"login", "verify_account", "grant_access"}
                and event.target == "account"
            ):
                add("ACCOUNT_ACCESS_REQUEST", event)
            if event.action == "provide_secret" and event.target == "authentication_secret":
                add("SECRET_DISCLOSURE_REQUEST", event)
            if event.action in {"execute", "enable_macros", "install"} and event.target in {
                "software",
                "document",
            }:
                add("EXECUTION_REQUEST", event)
            if event.action in {"pay", "transfer_money"} and event.target == "money":
                add("PAYMENT_REQUEST", event)
            if _coercive(event):
                add("COERCIVE_ACTION_REQUEST", event)
            if event.action == "analysis_manipulation" and event.target == "analysis_policy":
                add("ANALYSIS_MANIPULATION", event)
    events = {event.id: event for event in packet.events}
    for relation in packet.relations:
        source, target = events[relation.source_event], events[relation.target_event]
        if (
            relation.kind == "prerequisite_for"
            and _direct(source)
            and _direct(target)
            and (
                source.action == "download"
                and target.action in {"execute", "enable_macros", "install"}
                and source.target in {"document", "software"}
                and target.target in {"document", "software"}
            )
        ):
            # Relation evidence must cover both event sources; unrelated evidence cannot qualify.
            if set(source.evidence_ids + target.evidence_ids) <= set(relation.evidence_ids):
                add("LINKED_EXECUTION_REQUEST", relation)
    for signal in packet.signals:
        if signal.kind in {"url_display_mismatch", "url_userinfo"}:
            add("URL_DECEPTION", signal)
        elif signal.kind == "analysis_manipulation":
            add("ANALYSIS_MANIPULATION", signal)
        else:
            add("PROGRAM_RULE_MATCH", signal)
    if safe_eligible(packet):
        for event in packet.events:
            add("NO_RISK_FACTS", event)
    options["EVIDENCE_INSUFFICIENT"] = [{"source_id": None, "evidence_refs": []}]
    if simulation:
        options["SIMULATED_ANALYSIS"] = [{"source_id": None, "evidence_refs": []}]
    return options


def allowed_event_uncertainties(packet, *, simulation=False):
    codes = []
    if packet.semantic_completeness != "complete":
        codes.append("SEMANTIC_INCOMPLETE")
    if packet.semantic_completeness == "unclear":
        codes.append("CONTEXT_AMBIGUOUS")
    if packet.semantic_completeness in {"unrepresentable", "incomplete", "limit_reached"}:
        codes.append("UNREPRESENTED_CONTENT")
    if packet.coverage.status != "complete":
        codes.append("SOURCE_INCOMPLETE")
    if (
        packet.signals
        or packet.review_required
        or not packet.rules_complete
        or packet.parser_warning_count
    ):
        codes.append("PROGRAM_REVIEW")
    if simulation:
        codes.append("SIMULATION")
    return codes


def validate_event_judgment(core, packet, mapping, *, simulation=False):
    core = EventDecisionCore.model_validate_json(core.model_dump_json(), strict=True)
    if not set(core.evidence_refs) <= set(mapping):
        raise ValueError("INVALID_EVIDENCE_REFERENCE")
    options = support_options(packet, simulation=simulation)
    sources = {
        item.id: item
        for group in (packet.events, packet.relations, packet.signals)
        for item in group
    }
    violations = []
    for code, binding in core.reason_slots.__dict__.items():
        if binding is None:
            continue
        source = sources.get(binding.source_id)
        own_refs = set(source.evidence_ids) if source is not None else set()
        selected_refs = set(binding.evidence_refs)
        condition = None
        if len(binding.evidence_refs) != len(selected_refs):
            condition = "evidence_duplicate"
        elif binding.source_id is not None and source is None:
            condition = "source_unknown"
        elif source is not None and not selected_refs:
            condition = "evidence_missing"
        elif source is not None and selected_refs != own_refs:
            condition = "evidence_not_linked"
        elif not any(
            binding.source_id == option["source_id"]
            and selected_refs == set(option["evidence_refs"])
            for option in options[code]
        ):
            condition = "qualification_missing"
        if condition is not None:
            source_kind = (
                "none"
                if binding.source_id is None
                else "event"
                if source in packet.events
                else "relation"
                if source in packet.relations
                else "signal"
                if source in packet.signals
                else "unavailable"
            )
            violations.append(
                EventSupportViolation(
                    reason_code=code,
                    condition=condition,
                    source_kind=source_kind,
                    available_evidence_count=len(own_refs),
                    matching_evidence_count=len(selected_refs & own_refs),
                    invalid_evidence_count=len(selected_refs - own_refs),
                )
            )
    if violations:
        raise EventSupportError(violations)
    reasons = set(core.reason_codes)
    if not reasons:
        raise ValueError("INSUFFICIENT_SUPPORT")
    if len(core.uncertainty_codes) != len(set(core.uncertainty_codes)) or not set(
        core.uncertainty_codes
    ) <= set(allowed_event_uncertainties(packet, simulation=simulation)):
        raise ValueError("UNSUPPORTED_UNCERTAINTY")
    if "NO_RISK_FACTS" in reasons and reasons & RISK_CODES:
        raise ValueError("CONTRADICTORY_REASON")
    if core.classification == "SAFE" and (
        not safe_eligible(packet) or reasons != {"NO_RISK_FACTS"} or core.uncertainty_codes
    ):
        raise ValueError("UNSUPPORTED_SAFE")
    if core.classification in {"PHISHING", "SUSPICIOUS"}:
        if "NO_RISK_FACTS" in reasons or not reasons & RISK_CODES:
            raise ValueError("UNSUPPORTED_RISK")
        if core.classification == "PHISHING" and not reasons & STRONG_CODES:
            raise ValueError("UNSUPPORTED_RISK")
    if not simulation and "SIMULATED_ANALYSIS" in reasons:
        raise ValueError("INVALID_SIMULATION_CLAIM")
    return core


def restore_event_judgment(core, mapping):
    from app.domain.llm_models import JudgmentOutput

    return JudgmentOutput(
        classification=core.classification,
        reason_codes=core.reason_codes,
        evidence_refs=[mapping[ref] for ref in core.evidence_refs],
        uncertainties=list(core.uncertainty_codes),
        scope_limitations=[],
        rationale="",
        explanations=[],
    )


def decode_event_core(value):
    return EventCoreResponse.model_validate(value, strict=True).decision


def _binding_schema(options):
    variants = []
    for binding in options:
        refs = binding["evidence_refs"]
        variants.append(
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["source_id", "evidence_refs"],
                "properties": {
                    "source_id": {"type": "null"}
                    if binding["source_id"] is None
                    else {"type": "string", "enum": [binding["source_id"]]},
                    "evidence_refs": {
                        "type": "array",
                        "minItems": len(refs),
                        "maxItems": len(refs),
                        "items": {"type": "string", "enum": refs} if refs else {"type": "string"},
                    },
                },
            }
        )
    # Exact set binding and no duplicates are independently rechecked at runtime.
    return {"anyOf": [{"type": "null"}, *variants]} if variants else {"type": "null"}


def decision_schema(packet, *, simulation=False):
    options = support_options(packet, simulation=simulation)
    definitions = {f"EventSlot_{code}": _binding_schema(values) for code, values in options.items()}
    branches = []
    for classification in ("SAFE", "SUSPICIOUS", "PHISHING", "UNKNOWN"):
        if classification == "SAFE" and not safe_eligible(packet):
            continue
        properties = {}
        for code in REASON_CODES:
            excluded = (classification == "SAFE" and code != "NO_RISK_FACTS") or (
                classification in {"PHISHING", "SUSPICIOUS"} and code == "NO_RISK_FACTS"
            )
            properties[code] = (
                {"type": "null"} if excluded else {"$ref": f"#/$defs/EventSlot_{code}"}
            )
        slots = {
            "type": "object",
            "additionalProperties": False,
            "required": list(REASON_CODES),
            "properties": properties,
        }
        witness_codes = (
            {"NO_RISK_FACTS"}
            if classification == "SAFE"
            else STRONG_CODES
            if classification == "PHISHING"
            else RISK_CODES
            if classification == "SUSPICIOUS"
            else set(REASON_CODES)
        )
        witnesses = []
        for code in sorted(witness_codes):
            if not options[code]:
                continue
            witness = deepcopy(slots)
            if code == "NO_RISK_FACTS":
                for risk_code in RISK_CODES:
                    witness["properties"][risk_code] = {"type": "null"}
            else:
                witness["properties"]["NO_RISK_FACTS"] = {"type": "null"}
            # No root union or Cartesian combinations. One finite selected-support witness.
            witness["properties"][code] = {"anyOf": _binding_schema(options[code])["anyOf"][1:]}
            witnesses.append(witness)
        if not witnesses:
            continue
        uncertainty_codes = (
            []
            if classification == "SAFE"
            else allowed_event_uncertainties(packet, simulation=simulation)
        )
        branches.append(
            {
                "type": "object",
                "additionalProperties": False,
                "required": ["classification", "reason_slots", "uncertainty_codes"],
                "properties": {
                    "classification": {"type": "string", "enum": [classification]},
                    "reason_slots": {"anyOf": witnesses},
                    "uncertainty_codes": {
                        "type": "array",
                        "maxItems": len(uncertainty_codes),
                        "items": {"type": "string", "enum": uncertainty_codes}
                        if uncertainty_codes
                        else {"type": "string"},
                    },
                },
            }
        )
    return {
        "title": "EventCoreResponse",
        "type": "object",
        "additionalProperties": False,
        "required": ["decision"],
        "properties": {"decision": {"anyOf": branches}},
        "$defs": definitions,
    }


def event_review_items(packet, mapping):
    items = []
    if packet.semantic_completeness != "complete":
        items.append(
            ReviewItem(
                code="EVENT_SEMANTIC_INCOMPLETE",
                message="模型的行為事實提取有未找到、語意不清、無法表示、未完成或數量上限情況，需對照原文確認。",
                evidence_refs=[mapping[ref] for ref in packet.inspected_evidence_ids],
            )
        )
    return items


def validate_event_run(mail, rules, model):
    if any(
        value is None
        for value in (model.event_extraction, model.event_handoff, model.event_decision_core)
    ):
        raise ValueError("MISSING_HANDOFF")
    packet, mapping = project_events(
        mail,
        rules,
        model.event_extraction,
        scope_id=model.event_handoff.scope_id,
        coverage=model.coverage,
    )
    if packet != model.event_handoff or mapping != model.event_evidence_map:
        raise ValueError("MISMATCHED_HANDOFF")
    core = validate_event_judgment(
        model.event_decision_core, packet, mapping, simulation=model.is_simulation
    )
    if restore_event_judgment(core, mapping) != model.judgment:
        raise ValueError("MISMATCHED_JUDGMENT")
    return packet, set(mapping.values())
