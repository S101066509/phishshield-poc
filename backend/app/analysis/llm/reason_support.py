# 檔案功能：共用理由與觀察資格，產生逐理由生成約束並驗證明確證據綁定及去識別診斷。
from copy import deepcopy

from app.domain.handoff_models import ReasonSupportError, SupportViolation

SUPPORT = {
    "CREDENTIAL_REQUEST": "credential_request",
    "URGENCY_FEAR": "urgency_fear",
    "IMPERSONATION": "impersonation",
    "GENERIC_SALUTATION": "generic_salutation",
    "URL_DECEPTION": "url_deception",
    "LANGUAGE_ANOMALY": "language",
    "ANALYSIS_OVERRIDE": "analysis_override",
    "AUTHENTICATION_UNVERIFIED": "authentication",
}
RISK_ASSESSMENTS = {"observed", "uncertain"}


def eligible_observations(packet, code):
    return [
        item
        for item in packet.observations
        if item.kind == SUPPORT.get(code)
        and item.assessment in RISK_ASSESSMENTS
        and item.evidence_ids
    ]


def issue(
    code,
    condition,
    observation=None,
    *,
    selected=False,
    references=(),
    packet=None,
    selected_ids=(),
):
    available = set(observation.evidence_ids) if observation else set()
    supplied = set(references)
    return SupportViolation(
        reason_code=code,
        condition=condition,
        expected_kind=SUPPORT.get(code),
        observation_kind=observation.kind if observation else None,
        assessment=observation.assessment if observation else None,
        observation_selected=selected,
        selected_kinds=[item.kind for item in packet.observations if item.id in selected_ids]
        if packet
        else [],
        referenced_kinds=[
            item.kind for item in packet.observations if set(item.evidence_ids) & supplied
        ]
        if packet
        else [],
        available_evidence_count=len(available),
        matching_evidence_count=len(supplied & available),
        invalid_evidence_count=len(supplied - available),
    )


def validate_flat_support(value, packet):
    violations = []
    for code in dict.fromkeys(value.reason_codes):
        if value.reason_codes.count(code) > 1:
            violations.append(issue(code, "duplicate_reason"))
        if code == "RISKY_ATTACHMENT":
            available = set(packet.risky_attachment_evidence_ids)
            supplied = set(value.evidence_refs)
            condition = (
                "assessment_not_supportive"
                if not packet.risky_attachment_extension or not available
                else "evidence_missing"
                if not value.evidence_refs
                else "evidence_not_linked"
                if not available & supplied
                else None
            )
            if condition:
                violations.append(
                    SupportViolation(
                        reason_code=code,
                        condition=condition,
                        available_evidence_count=len(available),
                        matching_evidence_count=len(supplied & available),
                        invalid_evidence_count=len(supplied - available),
                    )
                )
            continue
        if code not in SUPPORT:
            continue
        observation = next(
            (item for item in packet.observations if item.kind == SUPPORT[code]), None
        )
        selected = observation is not None and observation.id in value.supporting_observation_ids
        condition = (
            "matching_observation_missing"
            if observation is None
            else "assessment_not_supportive"
            if observation.assessment not in RISK_ASSESSMENTS
            else "observation_not_selected"
            if not selected
            else "evidence_missing"
            if not value.evidence_refs
            else "evidence_not_linked"
            if not set(observation.evidence_ids) & set(value.evidence_refs)
            else None
        )
        if condition:
            violations.append(
                issue(
                    code,
                    condition,
                    observation,
                    selected=selected,
                    references=value.evidence_refs,
                    packet=packet,
                    selected_ids=value.supporting_observation_ids,
                )
            )
    if violations:
        raise ReasonSupportError(violations)


def proposal_fields(proposal):
    """Flatten only pairs explicitly selected by B. Never look up/append omitted evidence."""
    units = proposal.reason_supports
    return dict(
        reason_codes=[unit.reason_code for unit in units],
        supporting_observation_ids=list(
            dict.fromkeys(unit.observation_id for unit in units if unit.observation_id is not None)
        ),
        evidence_refs=list(dict.fromkeys(ref for unit in units for ref in unit.evidence_refs)),
    )


def validate_bound_support(value, packet):
    if value.reason_supports is None:
        return  # Fully validated flat responses retain the original policy, not repaired pairs.
    observations = {item.id: item for item in packet.observations}
    seen, violations = set(), []
    for unit in value.reason_supports:
        code = unit.reason_code
        observation = observations.get(unit.observation_id)
        condition = None
        if code in seen:
            condition = "duplicate_reason"
        elif code == "RISKY_ATTACHMENT":
            available = set(packet.risky_attachment_evidence_ids)
            supplied = set(unit.evidence_refs)
            if unit.observation_id is not None:
                condition = "observation_kind_mismatch"
            elif not packet.risky_attachment_extension or not available:
                condition = "assessment_not_supportive"
            elif not unit.evidence_refs:
                condition = "evidence_missing"
            elif not supplied <= available:
                condition = "evidence_not_linked"
            if condition:
                violations.append(
                    SupportViolation(
                        reason_code=code,
                        condition=condition,
                        observation_kind=observation.kind if observation else None,
                        assessment=observation.assessment if observation else None,
                        observation_selected=unit.observation_id
                        in value.supporting_observation_ids,
                        selected_kinds=[
                            item.kind
                            for item in packet.observations
                            if item.id in value.supporting_observation_ids
                        ],
                        available_evidence_count=len(available),
                        matching_evidence_count=len(supplied & available),
                        invalid_evidence_count=len(supplied - available),
                    )
                )
            seen.add(code)
            continue
        elif unit.observation_id is not None and observation is None:
            condition = "observation_unknown"
        elif code in SUPPORT and observation is None:
            condition = "matching_observation_missing"
        elif code in SUPPORT and observation.kind != SUPPORT[code]:
            condition = "observation_kind_mismatch"
        elif code in SUPPORT and observation.assessment not in RISK_ASSESSMENTS:
            condition = "assessment_not_supportive"
        elif observation is not None and not unit.evidence_refs:
            condition = "evidence_missing"
        elif unit.evidence_refs and (
            observation is None or not set(unit.evidence_refs) <= set(observation.evidence_ids)
        ):
            condition = "evidence_not_linked"
        if condition:
            violations.append(
                issue(
                    code,
                    condition,
                    observation,
                    selected=unit.observation_id in value.supporting_observation_ids,
                    references=unit.evidence_refs,
                    packet=packet,
                    selected_ids=value.supporting_observation_ids,
                )
            )
        seen.add(code)
    if violations:
        raise ReasonSupportError(violations)
    if any(getattr(value, name) != expected for name, expected in proposal_fields(value).items()):
        raise ReasonSupportError(
            [issue(value.reason_supports[0].reason_code, "support_fields_mismatch")],
            "INCONSISTENT_REASON_SUPPORT",
        )


def bound_support_schema(base, packet, *, simulation=False):
    """Each branch fixes one eligible code/id pair and limits refs to that observation."""
    options = []
    risks = any(item.assessment in RISK_ASSESSMENTS for item in packet.observations)

    def branch(code, observation=None):
        result = deepcopy(base)
        props = result["properties"]
        props["reason_code"] = {"type": "string", "const": code}
        props["observation_id"] = (
            {"type": "string", "const": observation.id} if observation else {"type": "null"}
        )
        props["evidence_refs"] = (
            {
                "type": "array",
                "maxItems": 100,
                "items": {"type": "string", "enum": list(observation.evidence_ids)},
                "minItems": 1,
            }
            if observation
            else {"type": "array", "maxItems": 0, "items": {"type": "string"}}
        )
        options.append(result)

    for code in SUPPORT:
        for observation in eligible_observations(packet, code):
            branch(code, observation)
    if packet.risky_attachment_extension and packet.risky_attachment_evidence_ids:
        result = deepcopy(base)
        props = result["properties"]
        props["reason_code"] = {"type": "string", "const": "RISKY_ATTACHMENT"}
        props["observation_id"] = {"type": "null"}
        props["evidence_refs"] = {
            "type": "array",
            "maxItems": 100,
            "items": {"type": "string", "enum": list(packet.risky_attachment_evidence_ids)},
            "minItems": 1,
        }
        options.append(result)
    if not risks:
        for observation in packet.observations:
            if observation.evidence_ids:
                branch("NO_RISK_OBSERVED", observation)
    # UNKNOWN may explain insufficient information without claiming a risk observation.
    branch("EVIDENCE_INSUFFICIENT")
    if simulation:
        branch("SIMULATED_ANALYSIS")
    return {"anyOf": options}
