# 檔案功能：由程式產生可直接複製的證據編號與原文，避免模型自行計算 Unicode 位移。

from app.domain.email_models import NormalizedEmail
from app.domain.evidence import EvidenceRegistry
from app.domain.explanation_policy import explanation_schema_node


def evidence_catalog(email: NormalizedEmail) -> dict[str, str]:
    registry = EvidenceRegistry(email)
    refs = [
        f"body:span:{start}-{min(start + 512, len(email.body_text))}"
        for start in range(0, len(email.body_text), 512)
    ]
    for kind, values in (
        ("url", email.urls),
        ("attachment", email.attachments_metadata),
        ("hidden", email.hidden_texts),
    ):
        refs.extend(f"{kind}:{index}" for index in range(len(values)))
    refs.extend(
        f"header:{name}:{index}"
        for name, values in email.headers.items()
        for index in range(len(values))
    )
    return {ref: registry.resolve(ref) for ref in refs}


def reference_schema(schema: dict, references) -> dict:
    """Constrain generated IDs to provided evidence; application validation remains mandatory."""
    from copy import deepcopy

    output = deepcopy(schema)
    refs = sorted(set(references))

    # JSON generation must express the same evidence obligations as runtime validators.
    def constrain(node):
        if isinstance(node, dict):
            if explanation_schema_node(node):
                observed, other = deepcopy(node), deepcopy(node)
                observed["properties"]["assessment"]["enum"] = ["observed"]
                observed["properties"]["evidence_refs"]["minItems"] = 1
                other["properties"]["assessment"]["enum"] = ["not_observed", "not_verified"]
                node.clear()
                node["anyOf"] = [observed, other]
            for value in list(node.values()):
                constrain(value)
        elif isinstance(node, list):
            for item in node:
                constrain(item)

    constrain(output)
    if "reason_codes" in output.get("properties", {}):
        output["properties"]["reason_codes"]["minItems"] = 1
        if refs and "evidence_refs" in output["properties"]:
            output["properties"]["evidence_refs"]["minItems"] = 1
    urls = [ref for ref in refs if ref.startswith("url:")]
    definitions = {}

    def walk(node):
        if isinstance(node, dict):
            for name, field in node.get("properties", {}).items():
                if name not in {"evidence_refs", "suspicious_url_refs"}:
                    continue
                values = urls if name == "suspicious_url_refs" else refs
                key = (
                    "ProvidedURLReference" if name == "suspicious_url_refs" else "ProvidedReference"
                )
                if values:
                    definitions[key] = {"type": "string", "enum": values}
                    field["items"] = {"$ref": f"#/$defs/{key}"}
                else:
                    field["maxItems"] = 0
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for value in node:
                walk(value)

    walk(output)
    output.setdefault("$defs", {}).update(definitions)
    return output
