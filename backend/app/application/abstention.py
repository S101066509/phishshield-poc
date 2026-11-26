# 檔案功能：只按已驗證觀察及B明選支持整理棄權狀態，不改分類、不還原或推測模型思考。
from app.analysis.llm.reason_support import RISK_ASSESSMENTS, SUPPORT
from app.domain.abstention_models import AbstentionSummary
from app.domain.handoff_models import KINDS


def build_abstention_summary(models, labels):
    if models.judgment.classification != "UNKNOWN":
        return None
    packet = models.handoff
    by_id = {item.id: item for item in packet.observations}
    reported = {item.kind for item in packet.observations if item.assessment in RISK_ASSESSMENTS}
    uncertain = {item.kind for item in packet.observations if item.assessment == "uncertain"}
    selected = {
        by_id[unit.observation_id].kind
        for unit in models.structured_judgment.reason_supports or []
        if unit.reason_code in SUPPORT
    }

    def ordered(kinds):
        return [kind for kind in KINDS if kind in kinds]

    if selected:
        reason = "SELECTED_RISK_WITHOUT_CONCLUSION"
        names = "、".join(labels[kind] for kind in ordered(selected))
        summary = (
            f"分析流程已完成，已採用「{names}」作為判讀參考，但風險判讀仍未形成安全或釣魚結論。"
        )
    elif reported:
        reason = "REPORTED_RISK_NOT_SELECTED"
        names = "、".join(labels[kind] for kind in ordered(reported))
        summary = (
            f"分析流程已完成，內容提取曾回報「{names}」，"
            "但風險判讀未採用這些觀察形成安全或釣魚結論。"
        )
    else:
        reason = "NO_REPORTED_RISK"
        summary = (
            "分析流程已完成；本次內容提取未回報風險訊號，風險判讀仍保留結論，不能以此確認信件安全。"
        )
    if uncertain:
        names = "、".join(labels[kind] for kind in ordered(uncertain))
        summary += f"其中「{names}」的提取結果仍有疑問。"
    steps = []
    if "impersonation" in reported or "authentication" in reported:
        steps.append("請透過既有聯絡管道確認寄件者身分與這項要求。")
    if "credential_request" in reported or "url_deception" in reported:
        steps.append("請從既有官方入口確認帳戶要求與連結用途，勿直接透過信內連結提供敏感資料。")
    if not steps:
        steps.append("請對照完整原文與實際往來情境；稱謂或措辭本身不能判定惡意。")
    return AbstentionSummary(
        reason=reason,
        reported_kinds=ordered(reported),
        uncertain_kinds=ordered(uncertain),
        selected_kinds=ordered(selected),
        unselected_kinds=ordered(reported - selected),
        summary=summary,
        next_steps=steps,
    ).model_dump(mode="json")
