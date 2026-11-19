# 檔案功能：以已保存分析產生內嵌中文字型的單筆、合併 PDF 或個別 PDF ZIP，保留原始版本。

import re
from datetime import datetime
from html import escape
from io import BytesIO
from pathlib import Path
from threading import Lock
from unicodedata import category
from zipfile import ZIP_DEFLATED, ZipFile
from zoneinfo import ZoneInfo

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer

FONT = "PhishShieldNotoTC"
pdfmetrics.registerFont(
    TTFont(FONT, str(Path(__file__).resolve().parents[1] / "assets/fonts/NotoSansTC-Regular.ttf"))
)
_GLYPHS = pdfmetrics.getFont(FONT).face.charToGlyph
_LOCK = Lock()
TAIPEI = ZoneInfo("Asia/Taipei")
LABELS = {
    "SAFE": "分析判定安全",
    "SUSPICIOUS": "需留意的訊號",
    "PHISHING": "釣魚風險",
    "UNKNOWN": "交由人員判斷",
}
CATEGORIES = {
    "authentication": "寄件與驗證資訊",
    "urgency_fear": "時間壓力與威脅",
    "generic_salutation": "稱謂與個人化",
    "url_structure": "網址結構",
    "language": "語系與措辭",
    "credential_request": "敏感資料要求",
    "impersonation": "身分冒用跡象",
    "url_deception": "網址偽裝跡象",
    "analysis_override": "干預分析的文字",
    "account_access": "帳戶登入或驗證要求",
    "secret_disclosure": "秘密資料要求",
    "software_execution": "軟體執行或安裝要求",
    "payment_request": "付款或轉帳要求",
    "coercive_request": "期限與聲稱後果",
    "linked_execution": "下載與執行的關係",
    "program_signal": "獨立文字或網址模式",
}
REVIEW_COPY = {
    "URL_BOUNDARY_AMBIGUOUS": (
        "連結範圍需要確認，信中文字可能與網址連在一起。",
        "請從原始信件確認完整網址，並向寄件單位核實。",
    ),
    "URL_PARSE_WARNING": ("部分網址格式無法可靠讀取。", "請對照原始信件中的連結，先不要直接開啟。"),
    "INTERNATIONALIZED_DOMAIN": (
        "連結使用國際化網域，字形可能與熟悉的網址相似。",
        "請核對正式網域，或從已知的官方入口進入。",
    ),
    "MISSING_SENDER": (
        "這份內容沒有提供寄件地址。",
        "可補上完整 EML，或透過既有聯絡方式確認寄件人。",
    ),
    "MISSING_SUBJECT": ("這份內容沒有提供主旨。", "請對照完整信件，確認其與內文及預期業務相符。"),
    "MULTIPLE_SENDERS": ("信件標頭列出多個寄件者。", "請向郵件管理人員確認實際寄件來源。"),
    "UNTRUSTED_AUTH_HEADERS": (
        "信內的驗證欄位尚未由可信郵件服務核實。",
        "請向郵件管理人員查核 SPF、DKIM、DMARC 結果。",
    ),
    "EMPTY_BODY": ("目前沒有取得可供分析的信件正文。", "請確認檔案內容，或重新匯入完整 EML。"),
    "UNSUPPORTED_INLINE_CONTENT": (
        "信件包含目前無法分析的內嵌內容。",
        "請在受控環境中交由資訊人員檢查。",
    ),
    "HIDDEN_CONTENT_PRESENT": (
        "信件內含可能未顯示於一般閱讀畫面的文字。",
        "請對照原文與解碼正文，確認是否影響信件意思。",
    ),
    "HTML_VISIBILITY_APPROXIMATE": (
        "靜態文字預覽可能與郵件軟體的畫面不同。",
        "請對照完整正文及原始信件，確認重要內容。",
    ),
}
ERROR_COPY = {
    "CORE_EVIDENCE_UNAVAILABLE": (
        "必要的原文證據無法取得，這次判斷未採用。請重新分析或對照完整原文。"
    ),
    "LLM_SCHEMA_UNSUPPORTED": "AI 請求格式未通過檢查，請由管理者確認服務設定。",
    "LLM_TIMEOUT": "AI 回覆逾時，請確認服務狀態後重新分析。",
    "ANALYSIS_TIMEOUT": "分析等待逾時，請確認服務狀態後重新分析。",
    "LLM_CONNECTION_LOST": "AI 連線中斷，重試後仍未完成。請確認連線後重新分析。",
    "LLM_RECONNECT_FAILED": "AI 連線未能恢復，請確認服務後重新分析。",
    "LLM_EVIDENCE_INVALID": (
        "AI 引用的原文未通過核對，這次未採用完整模型結論。請對照原文或重新分析。"
    ),
    "LLM_OUTPUT_INVALID": "AI 回覆無法完整讀取，請重新分析。",
    "LLM_NOT_CONFIGURED": "尚未設定 AI 服務，請完成環境變數設定後重新分析。",
    "INPUT_TOO_LARGE": "信件超過大小限制，請使用 2 MB 以內的單封 EML 或 TXT。",
    "PARSE_FAILED": "信件未能完整讀取，請重新匯入完整 EML 或 UTF-8 TXT。",
}


def _unique(values):
    return list(
        dict.fromkeys(value.strip() for value in values if isinstance(value, str) and value.strip())
    )


def _next_step(text):
    if re.search(r"網址|連結|URL|網站", text, re.I):
        return "建議從已知的官方入口查證，先不要點擊信內連結。"
    if re.search(r"寄件|身分|身份|SPF|DKIM|DMARC", text, re.I):
        return "建議透過既有聯絡方式確認寄件人，必要時請郵件管理人員協助。"
    return "建議向熟悉這項業務的聯絡人確認，使用既有聯絡電話或通訊管道。"


def _reader_notes(record, model):
    details = _unique(
        [
            *model.get("uncertainties", []),
            *model.get("scope_limitations", []),
            *(
                item.get("explanation")
                for item in model.get("explanations", [])
                if item.get("assessment") == "not_verified"
            ),
        ]
    )
    notes = [(text, _next_step(text)) for text in details]
    reviews = [
        *record.get("review_items", []),
        *(record.get("analysis_explanation") or {}).get("review_items", []),
    ]
    for item in reviews:
        code = item.get("code", "")
        copy = REVIEW_COPY.get(code)
        if not copy and re.search("CHARSET|DECODE|MIME|HEADER", code):
            copy = (
                "信件的編碼或格式有異常，部分內容可能無法正確讀取。",
                "請對照原始信件，若有亂碼或缺漏，重新匯入完整 EML。",
            )
        if not copy and re.search("UNICODE|MIXED_SCRIPT", code):
            copy = (
                "信件含特殊字元或混用字形，可能影響閱讀。",
                "請對照原文，確認寄件地址、品牌名稱與網址。",
            )
        if copy and copy not in notes:
            notes.append(copy)
    if not notes and any(item.get("code") != "SIMULATED_ANALYSIS" for item in reviews):
        notes.append(
            (
                "現有信件資訊仍有需要人員確認之處。",
                "建議對照完整信件，向既有聯絡人確認內容及要求是否符合預期。",
            )
        )
    return notes


def _text(value, limit=4000):
    text = str(value if value is not None else "未記錄")
    # Keep unsupported glyphs and invisible formatting controls visible in evidence.
    text = "".join(
        char
        if char in "\n\t" or (ord(char) in _GLYPHS and category(char) != "Cf")
        else f"[U+{ord(char):04X}]"
        for char in text
    )
    text = "".join(char for char in text if char in "\n\t" or ord(char) >= 32)
    if len(text) > limit:
        text = text[:limit] + "\n（內容節錄，完整資料請於網站檢視）"
    return escape(text).replace("\n", "<br/>")


def _date(value):
    if not value:
        return "未記錄"
    try:
        date = datetime.fromisoformat(value)
        return date.astimezone(TAIPEI).strftime("%Y/%m/%d %H:%M:%S") if date.tzinfo else value
    except (TypeError, ValueError):
        return str(value)


def _model_state(record):
    state = record.get("model_analysis") or {}
    if record.get("simulation") or "SIMULATED_ANALYSIS" in state.get("reason_codes", []):
        return "離線模擬"
    activated, completed = state.get("activated"), state.get("completed")
    if (
        not isinstance(activated, bool)
        or not isinstance(completed, bool)
        or (completed and not activated)
    ):
        return "模型狀態未記錄"
    if completed:
        return "模型已完成"
    return "模型未完成" if activated else "模型未啟用"


def _pdf(records):
    buffer = BytesIO()
    styles = {
        "title": ParagraphStyle(
            "title", fontName=FONT, fontSize=20, leading=29, textColor=colors.HexColor("#3b627b")
        ),
        "heading": ParagraphStyle(
            "heading",
            fontName=FONT,
            fontSize=12,
            leading=19,
            spaceBefore=17,
            spaceAfter=6,
            keepWithNext=True,
            textColor=colors.HexColor("#3b627b"),
        ),
        "conclusion": ParagraphStyle(
            "conclusion",
            fontName=FONT,
            fontSize=17,
            leading=26,
            textColor=colors.HexColor("#3b627b"),
            backColor=colors.HexColor("#f0f5f7"),
            borderPadding=12,
            spaceBefore=8,
            spaceAfter=24,
            wordWrap="CJK",
        ),
        "body": ParagraphStyle(
            "body",
            fontName=FONT,
            fontSize=10,
            leading=16,
            spaceAfter=7,
            wordWrap="CJK",
            alignment=TA_LEFT,
            splitLongWords=True,
        ),
    }
    story = []

    def paragraph(value, style="body", limit=4000):
        story.append(Paragraph(_text(value, limit), styles[style]))

    def limited(items, maximum):
        if len(items) > maximum:
            paragraph("此區僅列部分項目，完整資料請於網站檢視。")
        return items[:maximum]

    for index, record in enumerate(records):
        if index:
            story.append(PageBreak())
        document = record.get("source_document") or {}
        mail = document.get("parsed") or {}
        explanation = record.get("analysis_explanation") or {}
        model = (explanation.get("model") or {}) if explanation.get("available") else {}
        classification = (
            "UNKNOWN" if record.get("status") == "FAILED" else record.get("final_classification")
        )
        paragraph("PhishShield 郵件分析報告", "title")
        story.append(Spacer(1, 5 * mm))
        paragraph(LABELS.get(classification, "尚未形成分類"), "conclusion")
        paragraph("信件主旨　" + (mail.get("subject") or "未提供主旨"))
        paragraph("寄件者　" + (mail.get("sender") or "未提供"))
        paragraph("分析時間（台北）　" + _date(record.get("created_at")))
        paragraph(
            "分析狀態　"
            + ("分析未完成" if record.get("status") == "FAILED" else "分析流程已完成")
            + "・"
            + _model_state(record)
        )
        if record.get("simulation"):
            paragraph("此份報告使用離線模擬結果，供操作流程測試。")
        presentation = explanation.get("presentation") or {}
        if presentation.get("status") == "degraded":
            paragraph("核心判斷已完成；詳細說明暫時無法整理，請對照所附原文。")
        if (record.get("coverage") or {}).get("status") == "incomplete":
            paragraph("本次僅涵蓋部分可分析內容，不能用來認定整封信件安全。請對照完整原文。")
        semantic = (record.get("analysis_reliability") or {}).get("semantic_extraction") or {}
        if (
            semantic.get("availability") == "recorded"
            and semantic.get("semantic_completeness") != "complete"
        ):
            paragraph(
                "行為提取仍需核對：模型未確認所有語意已完整表示；"
                "原文已送達不代表行為提取正確或完整。"
            )
        paragraph("判斷摘要", "heading")
        if model:
            paragraph(model.get("source_note") or "此筆舊紀錄未記錄理由來源，請對照原文。")
        paragraph(
            model.get("rationale")
            or "目前沒有可採用的完整 AI 判斷理由。請對照信件內容及下方建議確認事項。"
        )
        evidence = {item["ref"]: item.get("text", "") for item in document.get("evidence", [])}
        evidence.update({item["ref"]: item.get("text", "") for item in model.get("evidence", [])})
        used_refs = set()

        def quoted(refs, evidence=evidence, used_refs=used_refs):
            for ref in refs:
                if ref not in used_refs and ref in evidence:
                    used_refs.add(ref)
                    paragraph("信中原文", "heading")
                    paragraph(evidence[ref], limit=2000)

        shown = set()
        for item in limited(model.get("explanations", []), 10):
            text = item.get("explanation")
            if item.get("assessment") == "not_verified" or not text or text in shown:
                continue
            shown.add(text)
            paragraph(CATEGORIES.get(item.get("category"), "信件內容觀察"), "heading")
            paragraph(text)
            quoted(item.get("evidence_refs", []))
        for item in limited(model.get("features", []), 100):
            text = item.get("description")
            if text and text not in shown:
                shown.add(text)
                paragraph(text)
                quoted(item.get("evidence_refs", []))
        findings = record.get("rule_findings", [])
        if findings:
            paragraph("信件中值得注意的內容", "heading")
        for item in limited(findings, 100):
            text = item.get("summary")
            if text and text not in shown:
                shown.add(text)
                paragraph(text)
                quoted(item.get("evidence_refs", []))
        quoted(model.get("evidence_refs", []))
        existing_reasons = set(_unique([model.get("rationale"), *shown]))
        indicators = [
            text
            for text in _unique(model.get("social_engineering_indicators") or [])
            if text not in existing_reasons
        ]
        if indicators:
            paragraph("社交工程手法", "heading")
        for text in limited(indicators, 100):
            paragraph(text)
        notes = _reader_notes(record, model)
        if notes:
            paragraph("建議確認事項", "heading")
        for detail, action in limited(notes, 100):
            paragraph(detail)
            paragraph(action)
        paragraph("原文與證據節錄", "heading")
        paragraph(
            document.get("display_body_text")
            or mail.get("body_text")
            or document.get("raw_text")
            or "此筆紀錄未保存原文。",
            limit=3000,
        )
        for ref, value in limited(list(evidence.items()), 100):
            if ref not in used_refs:
                paragraph("引用原文", "heading")
                paragraph(value, limit=2000)
        if record.get("errors"):
            paragraph("分析未完成原因", "heading")
        for item in record.get("errors", []):
            paragraph(
                ERROR_COPY.get(item.get("code"), "分析服務未能完成本次處理，請確認服務後重試。")
            )
        paragraph("分析結果供人員對照原文與證據判讀，安全性仍須配合實際情境確認。")

    def footer(canvas, doc):
        canvas.setFont(FONT, 8)
        canvas.setFillColor(colors.HexColor("#615c6b"))
        canvas.setProducer("PhishShield")
        canvas.setCreator("PhishShield")
        canvas.drawString(18 * mm, 12 * mm, "PhishShield")
        canvas.drawRightString(A4[0] - 18 * mm, 12 * mm, f"第 {doc.page} 頁")

    SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=22 * mm,
        title="PhishShield 郵件分析報告",
        author="PhishShield",
    ).build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


def export_reports(records: list[dict], format: str = "pdf") -> bytes:
    # Serialize font subsetting while keeping CPU work outside the HTTP event loop.
    with _LOCK:
        if format == "pdf":
            return _pdf(records)
        output = BytesIO()
        with ZipFile(output, "w", compression=ZIP_DEFLATED) as archive:
            for index, record in enumerate(records, 1):
                archive.writestr(f"phishshield-report-{index:03d}.pdf", _pdf([record]))
        return output.getvalue()
