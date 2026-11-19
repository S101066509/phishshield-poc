# 檔案功能：共用說明 assessment 與引用資格，避免生成與驗證依類名分歧。
from typing import Literal, get_args

ExplanationAssessment = Literal["observed", "not_observed", "not_verified"]


def validate_explanation_reference(assessment, references):
    if assessment == "observed" and not references:
        raise ValueError("OBSERVATION_REQUIRES_EVIDENCE")


def explanation_schema_node(node):
    properties = node.get("properties", {})
    return (
        set(properties.get("assessment", {}).get("enum", []))
        == set(get_args(ExplanationAssessment))
        and properties.get("evidence_refs", {}).get("type") == "array"
    )
