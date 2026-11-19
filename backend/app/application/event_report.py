# 檔案功能：依通過驗證的行為事實、程式訊號與原文引用產生可追溯的中文說明。

from app.application.deterministic_report import base_model

SOURCE_NOTE = (
    "本說明由程式依已驗證的行為事實與原文引用整理，不是模型原話。"
    "行為事實是模型對信中表述的提取；程式訊號另行標示，均不代表已連線查證。"
)
ACTION_LABELS = {
    "login": "登入帳戶",
    "change_password": "變更密碼",
    "verify_account": "驗證帳戶或恢復存取",
    "provide_secret": "提供認證或金融秘密",
    "grant_access": "授予帳戶存取權限",
    "view_document": "查看文件",
    "download": "下載內容",
    "execute": "執行檔案或指令",
    "enable_macros": "啟用巨集",
    "install": "安裝軟體",
    "pay": "付款",
    "transfer_money": "轉帳",
    "call_back": "回撥電話",
    "analysis_manipulation": "干預分析指令或結果",
    "other": "目前類型不能充分表達的行為",
}
PARTICIPANT_LABELS = {
    "sender": "寄件方",
    "recipient": "收件方",
    "third_party": "第三方",
    "unspecified": "未指定",
}
TARGET_LABELS = {
    "account": "帳戶",
    "authentication_secret": "認證秘密",
    "money": "金錢",
    "document": "文件",
    "software": "軟體",
    "analysis_policy": "分析指令或政策",
    "other": "其他類型",
    "unspecified": "未指定",
}
CONTEXT_LABELS = {
    "direct_request": "直接要求",
    "reported": "轉述",
    "quoted_example": "引用示例",
    "security_education": "安全教育內容",
    "notification": "事件通知",
    "unclear": "語境不明",
}
CHANNEL_LABELS = {
    "mail_link": "信內連結",
    "attachment": "信中附件",
    "reply": "回信",
    "phone": "電話",
    "claimed_existing_entry": "信中聲稱的既有入口",
    "unspecified": "未指定的管道",
    "unclear": "不明確的管道",
}
DEADLINE_LABELS = {
    "immediate": "立即",
    "within_day": "一日內",
    "within_week": "一週內",
    "later": "較晚的指定時間",
    "unclear": "期限不明確",
}
CONSEQUENCE_LABELS = {
    "account_disabled": "帳戶停用",
    "financial_loss": "金錢損失",
    "data_loss": "資料損失",
    "service_interruption": "服務中斷",
    "unclear": "後果不明確",
}
SECRET_LABELS = {
    "password": "密碼",
    "otp": "一次性驗證碼（OTP）",
    "recovery_code": "復原碼",
    "payment_secret": "金融秘密",
}
RELATION_LABELS = {
    "prerequisite_for": "條件與動作的關係",
    "consequence_of": "動作與聲稱後果的關係",
    "refers_to": "跨句對應關係",
    "follows": "先後關係",
}
SIGNAL_LABELS = {
    "url_display_mismatch": "連結顯示文字與實際導向不一致",
    "url_userinfo": "網址含可能混淆導向的使用者資訊",
    "url_ip_host": "網址直接以 IP 位址作為主機",
    "credential_pattern": "敏感資料要求的文字模式",
    "urgency_pattern": "催促或威脅的文字模式",
    "analysis_manipulation": "試圖干預分析的文字模式",
    "attachment_extension": "檔名具有需留意的副檔名",
    "sender_reply_mismatch": "寄件與回覆地址不一致",
    "short_url": "連結使用縮網址服務",
    "redirect_parameter": "網址參數含其他導向網址",
}
REASONS = {
    "ACCOUNT_ACCESS_REQUEST": (
        "account_access",
        "帳戶登入或驗證要求",
        "請從既有入口確認要求，避免直接依信件路徑登入。",
    ),
    "SECRET_DISCLOSURE_REQUEST": (
        "secret_disclosure",
        "秘密資料要求",
        "請另行確認用途，勿透過信件提供密碼、驗證碼或復原碼。",
    ),
    "EXECUTION_REQUEST": (
        "software_execution",
        "軟體執行或安裝要求",
        "請由資訊人員確認檔案與操作，勿直接啟用巨集或執行。",
    ),
    "PAYMENT_REQUEST": (
        "payment_request",
        "付款或轉帳要求",
        "請使用既有電話與付款流程，獨立確認收款與交易。",
    ),
    "COERCIVE_ACTION_REQUEST": (
        "coercive_request",
        "期限與聲稱後果綁定的操作要求",
        "請另行確認時限及處置，避免因催促而略過查證。",
    ),
    "LINKED_EXECUTION_REQUEST": (
        "linked_execution",
        "有關聯的下載與執行要求",
        "請對照兩項動作的原文關係，交由資訊人員確認。",
    ),
    "ANALYSIS_MANIPULATION": (
        "analysis_override",
        "干預分析的文字",
        "請對照原文與其他業務內容，不應將這段文字視為系統指令。",
    ),
    "URL_DECEPTION": (
        "url_deception",
        "網址導向的差異",
        "請核對完整網域與顯示文字，改從已知的官方入口查證。",
    ),
    "PROGRAM_RULE_MATCH": (
        "program_signal",
        "獨立文字或網址模式",
        "模式命中仍需配合信件內容與既有業務背景判斷。",
    ),
}
UNCERTAINTIES = {
    "CONTEXT_AMBIGUOUS": "部分行為的語境或否定範圍仍不明確，請對照原文。",
    "SEMANTIC_INCOMPLETE": "模型提取未確認完整；原文已送達不代表所有行為都已被正確理解。",
    "UNREPRESENTED_CONTENT": "部分表述無法由目前的行為類型充分表示，請對照原文。",
    "UNMAPPED_CONTENT": "部分表述尚未完整映射為行為事實，請對照原文。",
    "SOURCE_INCOMPLETE": "部分可分析來源未完整送達模型，不能認定整封信件安全；請對照完整信件。",
    "PROGRAM_REVIEW": "程式發現需進一步核對的來源或模式，請對照原文。",
    "SIMULATION": "這次使用離線模擬，不能作為真實風險判斷。",
}


def event_description(event):
    """Render only closed fields; no model-supplied prose or verified-origin claims."""
    action = ACTION_LABELS[event.action]
    context = CONTEXT_LABELS[event.context]
    polarity = {
        "affirmed": "肯定提及",
        "negated": "明確否定",
        "unclear": "否定範圍不明",
    }[event.polarity]
    clauses = [f"模型將所引內容提取為「{context}／{polarity}：{action}」"]
    if event.actor != "unspecified" or event.recipient != "unspecified":
        clauses.append(
            "行為者為"
            + PARTICIPANT_LABELS[event.actor]
            + "，接受方為"
            + PARTICIPANT_LABELS[event.recipient]
        )
    if event.target != "unspecified":
        clauses.append("對象類型為" + TARGET_LABELS[event.target])
    if event.channel not in {"unspecified", "unclear"}:
        clauses.append(f"管道為{CHANNEL_LABELS[event.channel]}")
    if event.secret_kind in SECRET_LABELS:
        clauses.append("所涉類型為" + SECRET_LABELS[event.secret_kind])
    if event.deadline in DEADLINE_LABELS:
        clauses.append("信中期限為" + DEADLINE_LABELS[event.deadline])
    if event.consequence in CONSEQUENCE_LABELS:
        clauses.append("信中聲稱後果為" + CONSEQUENCE_LABELS[event.consequence])
    return "；".join(clauses) + "。這是模型對表述的解讀，請核對原文。"


def build_event_model(models, evidence):
    packet = models.event_handoff
    mapping = models.event_evidence_map
    core = models.event_decision_core
    output = base_model(models, evidence)
    output["source_note"] = SOURCE_NOTE
    items = {item.id: item for item in [*packet.events, *packet.relations, *packet.signals]}
    explanations = []
    for reason, binding in core.reason_slots:
        if binding is None or reason not in REASONS:
            continue
        category, title, advice = REASONS[reason]
        source = items[binding.source_id]
        if source.source == "parser_rules":
            text = (
                "程式在這封信中比對到「"
                + SIGNAL_LABELS.get(source.kind, "已定義的文字或網址模式")
                + "」。這表示符合模式，尚未證實惡意。"
            )
        elif source.id in {item.id for item in packet.events}:
            text = event_description(source)
        else:
            source_event = items[source.source_event]
            target_event = items[source.target_event]
            text = (
                "模型提取了「"
                + RELATION_LABELS.get(source.kind, "兩項行為的關係")
                + "」。"
                + event_description(source_event)
                + event_description(target_event)
            )
        explanations.append(
            {
                "category": category,
                "assessment": "observed",
                "explanation": title + "：" + text + advice,
                "evidence_refs": [mapping[ref] for ref in binding.evidence_refs],
            }
        )
    output["explanations"] = explanations
    adopted = {
        unit.source_id for code, unit in core.reason_slots if unit is not None and code in REASONS
    }
    for relation in packet.relations:
        if relation.id in adopted:
            # The selected relationship already explains both endpoints above.
            adopted.update((relation.source_event, relation.target_event))
    output["features"] = [
        {
            "feature_type": "event_fact",
            "category": "event_fact",
            "description": "未採用為風險理由的行為提取：" + event_description(event),
            "evidence_refs": [mapping[ref] for ref in event.evidence_ids],
        }
        for event in packet.events
        if event.id not in adopted
    ]
    output["uncertainties"] = [
        UNCERTAINTIES.get(code, "仍有資訊不足或語意不清之處，請對照原文。")
        for code in core.uncertainty_codes
    ]
    if packet.semantic_completeness != "complete":
        output["uncertainties"].append(
            "模型提取未確認完整，需對照原文；這與來源是否完整送達模型是不同狀態。"
        )
    output["uncertainties"] = list(dict.fromkeys(output["uncertainties"]))
    if core.classification == "SAFE":
        output["rationale"] = (
            "已驗證核心採用模型聲稱已完成提取中的無風險支持，現有事實未形成風險理由。"
            "這不是寄件身分或網址安全的外部驗證，仍請依實際業務背景確認。"
        )
    elif core.classification == "UNKNOWN":
        output["rationale"] = (
            "核心分析已完成，但現有行為事實與程式訊號不足以形成安全或釣魚結論；"
            "已支持的事實仍保留，請對照原文交由人員判斷。"
        )
    else:
        selected = [
            REASONS[reason][1] for reason, unit in core.reason_slots if unit and reason in REASONS
        ]
        output["rationale"] = (
            "核心依「" + "、".join(selected) + "」提出風險判斷；"
            "具體行為屬模型提取，程式模式另行標示。請核對引文並透過既有管道確認。"
        )
    return output
