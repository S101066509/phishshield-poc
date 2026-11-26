# 檔案功能：僅依已驗證核心與觀察產生中文說明，不生成新風險、引文或外部查證結論。
SOURCE_NOTE = (
    "系統依已驗證的模型擷取觀察與原文引用整理說明；不是模型原話，亦未連線查證寄件者或網址。"
)


class CoreEvidenceUnavailable(ValueError):
    pass


def base_model(models, evidence):
    return dict(
        source_note=SOURCE_NOTE,
        classification=models.judgment.classification.value,
        reason_codes=models.judgment.reason_codes,
        evidence_refs=models.judgment.evidence_refs,
        evidence=evidence,
        rationale="核心判斷已通過驗證；詳細說明暫時無法產生，請對照所附原文。",
        explanations=[],
        features=[],
        social_engineering_indicators=[],
        uncertainties=[],
        scope_limitations=["未連線驗證寄件者簽章、網址信譽或附件內容。"],
    )


def build_deterministic_model(models, evidence, labels, uncertainty_labels):
    output = base_model(models, evidence)
    by_id = {item.id: item for item in models.handoff.observations}
    mapping = models.handoff_evidence_map
    explanations = []
    suggestions = {
        "credential_request": "請透過既有服務入口確認要求，勿直接提供密碼或驗證碼。",
        "urgency_fear": "請另行確認時限與處置要求，避免因催促而略過查證。",
        "url_deception": "請對照完整網址與顯示文字，經既有官方入口確認。",
        "impersonation": "請透過既有聯絡管道確認寄件者身分。",
        "authentication": "寄件驗證聲明尚未外部驗證，請向郵件管理者確認。",
        "generic_salutation": "一般稱謂只是弱訊號，請搭配其他內容判斷。",
        "language": "語系或措辭差異只是弱訊號，請對照原文與往來情境。",
        "analysis_override": "請對照試圖影響分析的文字與其他郵件內容。",
    }
    for unit in models.structured_judgment.reason_supports or []:
        if unit.reason_code == "RISKY_ATTACHMENT":
            explanations.append(
                dict(
                    category="risky_attachment",
                    assessment="observed",
                    explanation=(
                        "規則標示「高風險附件副檔名」（僅依檔名中繼資料，未開啟或分析內容）；"
                        "請核對所引附件並透過既有聯絡管道確認來源。"
                    ),
                    evidence_refs=[mapping[ref] for ref in unit.evidence_refs],
                )
            )
            continue
        observation = by_id.get(unit.observation_id)
        if not observation or unit.reason_code in {
            "NO_RISK_OBSERVED",
            "EVIDENCE_INSUFFICIENT",
            "SIMULATED_ANALYSIS",
        }:
            continue
        state = (
            "模型擷取結果標示"
            if observation.assessment == "observed"
            else "模型擷取結果對此仍有疑問"
        )
        explanations.append(
            dict(
                category=observation.kind,
                assessment=observation.assessment,
                explanation=f"{state}「{labels[observation.kind]}」；請以所引原文核對。{suggestions[observation.kind]}",
                evidence_refs=[mapping[ref] for ref in unit.evidence_refs],
            )
        )
    output["explanations"] = explanations
    output["uncertainties"] = [uncertainty_labels[code] for code in models.judgment.uncertainties]
    if models.judgment.classification == "SAFE":
        output["rationale"] = (
            "核心所採用的模型觀察未標示風險訊號，並附上已檢視的原文。這不等同外部身分或網址安全驗證。"
        )
    elif models.judgment.classification == "UNKNOWN":
        output["rationale"] = (
            "核心分析已完成，但現有觀察不足以形成安全或釣魚結論；請對照原文交由人員判斷。"
        )
    else:
        kinds = list(
            dict.fromkeys(
                labels[by_id[item.observation_id].kind]
                for item in models.structured_judgment.reason_supports
                if item.observation_id in by_id
                and item.reason_code not in {"EVIDENCE_INSUFFICIENT", "NO_RISK_OBSERVED"}
            )
        )
        has_attachment = any(
            item.reason_code == "RISKY_ATTACHMENT"
            for item in models.structured_judgment.reason_supports
        )
        if kinds and has_attachment:
            output["rationale"] = (
                "核心依模型擷取的"
                + "、".join(kinds)
                + "訊號及規則標示的高風險附件副檔名提出風險建議；"
                "請核對所引原文，並透過既有聯絡管道確認。"
            )
        elif has_attachment:
            output["rationale"] = (
                "核心依規則標示的高風險附件副檔名（僅依檔名中繼資料，未分析內容）提出風險建議；"
                "請核對所引附件，並透過既有聯絡管道確認。"
            )
        else:
            output["rationale"] = (
                "核心依模型擷取的"
                + "、".join(kinds)
                + "訊號提出風險建議；請核對所引原文，並透過既有聯絡管道確認。"
            )
    return output
