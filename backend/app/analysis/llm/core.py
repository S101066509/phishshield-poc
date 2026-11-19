# 檔案功能：產生固定理由槽位的受限核心 Schema，並獨立驗證分類與支持，不生成說明。
from typing import get_args

from app.analysis.llm.reason_support import SUPPORT, eligible_observations, proposal_fields
from app.domain.handoff_models import DecodedCore, Reason, ReasonSupport

CORE_NOTE = "核心判斷已通過驗證；人員說明由程式另行整理。"


def safe_eligible(packet):
    return (
        not any(item.assessment in {"observed", "uncertain"} for item in packet.observations)
        and packet.rules_complete
        and not packet.rule_count
        and not packet.parser_warning_count
        and not packet.review_required
        and packet.coverage.status == "complete"
    )


def core_judgment(core):
    units = [
        ReasonSupport(reason_code=code, **binding.model_dump())
        for code, binding in core.reason_slots
        if binding is not None
    ]
    # No missing unit/reference is supplied from A. Empty selections fail as core schema/support.
    if not units:
        raise ValueError("INSUFFICIENT_SUPPORT")

    class Selected:
        reason_supports = units

    return DecodedCore(
        core=core,
        classification=core.classification,
        **proposal_fields(Selected()),
        uncertainty_codes=core.uncertainty_codes,
        rationale=CORE_NOTE,
        explanations=[],
        reason_supports=units,
    )


def validate_core(core, packet, mapping, *, simulation=False):
    from app.analysis.llm.handoff import validate_judgment

    value = core_judgment(core)
    if core.classification in {"PHISHING", "SUSPICIOUS"} and not any(
        code in SUPPORT and code != "AUTHENTICATION_UNVERIFIED" for code in value.reason_codes
    ):
        raise ValueError("UNSUPPORTED_RISK")
    validate_judgment(value, packet, mapping, simulation=simulation)
    if core.classification == "SAFE" and not safe_eligible(packet):
        raise ValueError("UNSUPPORTED_SAFE")
    return value


def core_schema(packet, *, simulation=False):
    """Object root; nested anyOf and linear witnesses, never enumerate reason combinations."""
    codes = get_args(Reason)
    definitions = {}
    selectable = []
    risks = []

    def binding(observation=None):
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["observation_id", "evidence_refs"],
            "properties": {
                "observation_id": {"type": "string", "const": observation.id}
                if observation
                else {"type": "null"},
                "evidence_refs": {
                    "type": "array",
                    "items": {"type": "string", "enum": list(observation.evidence_ids)},
                    "minItems": 1,
                    "maxItems": 4,
                }
                if observation
                else {"type": "array", "items": {"type": "string"}, "maxItems": 0},
            },
        }

    for code in codes:
        options = (
            [binding(item) for item in eligible_observations(packet, code)]
            if code in SUPPORT
            else []
        )
        if (
            code == "NO_RISK_OBSERVED"
            and not any(
                item.assessment in {"observed", "uncertain"} for item in packet.observations
            )
            and packet.coverage.status == "complete"
        ):
            options = [binding(item) for item in packet.observations if item.evidence_ids]
        if code == "EVIDENCE_INSUFFICIENT" or (code == "SIMULATED_ANALYSIS" and simulation):
            options = [binding()]
        if options:
            definitions[code] = options[0] if len(options) == 1 else {"anyOf": options}
            selectable.append(code)
            if code in SUPPORT and code != "AUTHENTICATION_UNVERIFIED":
                risks.append(code)

    def slots(witness, *, safe=False):
        properties = {}
        for code in codes:
            chosen = {"$ref": f"#/$defs/{code}"}
            if code == witness:
                properties[code] = chosen
            elif code in selectable and not safe:
                properties[code] = {"anyOf": [{"type": "null"}, chosen]}
            else:
                properties[code] = {"type": "null"}
        return {
            "type": "object",
            "additionalProperties": False,
            "required": list(codes),
            "properties": properties,
        }

    from app.analysis.llm.handoff import allowed_uncertainties

    uncertainties = allowed_uncertainties(packet, simulation=simulation)

    def decision(classifications, witnesses, *, safe=False):
        return {
            "type": "object",
            "additionalProperties": False,
            "required": ["classification", "reason_slots", "uncertainty_codes"],
            "properties": {
                "classification": {"type": "string", "enum": classifications},
                "reason_slots": {"anyOf": [slots(code, safe=safe) for code in witnesses]},
                "uncertainty_codes": {
                    "type": "array",
                    "maxItems": 0 if safe or not uncertainties else 10,
                    "items": {"type": "string", "enum": uncertainties}
                    if uncertainties
                    else {"type": "string"},
                },
            },
        }

    branches = [decision(["UNKNOWN"], selectable)]
    if risks:
        branches.append(decision(["PHISHING", "SUSPICIOUS"], risks))
    if safe_eligible(packet):
        branches.append(decision(["SAFE"], ["NO_RISK_OBSERVED"], safe=True))
    return {
        "title": "CoreResponse",
        "type": "object",
        "additionalProperties": False,
        "required": ["decision"],
        "properties": {"decision": {"anyOf": branches}},
        "$defs": definitions,
    }


def check_schema_subset(schema):
    """Conservative subset already used by this adapter; not a claim of live server acceptance."""
    allowed = {
        "title",
        "description",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "enum",
        "const",
        "anyOf",
        "$defs",
        "$ref",
        "items",
        "minItems",
        "maxItems",
        "minimum",
        "maximum",
        "minLength",
        "maxLength",
        "pattern",
        "default",
    }
    if schema.get("type") != "object" or any(
        key in schema for key in ("anyOf", "oneOf", "allOf", "$ref")
    ):
        raise ValueError("SCHEMA_SUBSET_UNSUPPORTED")

    def visit(node):
        if isinstance(node, dict):
            if any(key not in allowed for key in node):
                raise ValueError("SCHEMA_SUBSET_UNSUPPORTED")
            for key, value in node.items():
                if key in {"properties", "$defs"}:
                    for child in value.values():
                        visit(child)
                elif key in {"items"}:
                    visit(value)
                elif key == "anyOf":
                    for child in value:
                        visit(child)
        return None

    visit(schema)
