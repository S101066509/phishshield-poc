# 檔案功能：提供本機分析、歷史及靜態介面 API，限制請求大小、來源並輸出去敏化錯誤。

import asyncio
from contextlib import asynccontextmanager
from datetime import date
from pathlib import Path
from typing import Annotated, Literal
from uuid import UUID

from fastapi import FastAPI, File, Form, Query, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy.exc import SQLAlchemyError
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.documentation import (
    ANALYSIS_RESPONSES,
    ANALYSIS_SCHEMA,
    COMMON_RESPONSES,
    DESCRIPTION,
    TAGS,
    UNSUPPORTED_RESPONSE,
    VALIDATION_RESPONSE,
    register_documentation,
)
from app.api.schemas import AnalyzeRequest, ModelStatusResponse, ReportExportRequest
from app.application.analysis_service import AnalysisService
from app.application.model_status import model_status
from app.application.report_export import export_reports
from app.config import AppSettings
from app.domain.enums import EmailSource
from app.domain.versions import (
    API_VERSION,
    DATABASE_SCHEMA_VERSION,
    DECISION_VERSION,
    EVALUATION_VERSION,
    LLM_PIPELINE_VERSION,
    LLM_SCHEMA_VERSION,
    PARSER_VERSION,
    PRODUCT_VERSION,
    REPORT_VERSION,
    RULESET_VERSION,
    UI_VERSION,
)
from app.infrastructure.db.repository import HistoryRepository

FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


def error_response(code: str, status: int):
    return JSONResponse(
        dict(
            error_code=code,
            status="FAILED",
            final_classification="UNKNOWN",
            analysis_completed=False,
            reason="本次請求未成功完成，請確認輸入或稍後重試。",
        ),
        status_code=status,
        headers={"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"},
    )


class RequestBoundary:
    def __init__(self, app, limit):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        headers = dict(scope.get("headers", []))
        if (
            scope.get("method") == "POST"
            and scope.get("path") in {"/api/v1/analyses", "/api/v1/rules"}
            and headers.get(b"content-type", b"").split(b";")[0] != b"application/json"
        ):
            return await error_response("UNSUPPORTED_MEDIA_TYPE", 415)(scope, receive, send)
        origin, host = headers.get(b"origin"), headers.get(b"host", b"")
        if origin is not None and origin not in {b"http://" + host, b"https://" + host}:
            return await error_response("ORIGIN_NOT_ALLOWED", 403)(scope, receive, send)
        raw_length = headers.get(b"content-length")
        if raw_length is not None:
            try:
                length = int(raw_length)
                if length < 0:
                    raise ValueError
            except ValueError:
                return await error_response("INVALID_CONTENT_LENGTH", 400)(scope, receive, send)
            if length > self.limit:
                return await error_response("REQUEST_TOO_LARGE", 413)(scope, receive, send)
        body = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > self.limit:
                        return await error_response("REQUEST_TOO_LARGE", 413)(scope, receive, send)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            return await error_response("UPLOAD_TIMEOUT", 408)(scope, receive, send)
        delivered = False

        async def buffered_receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        async def secured_send(message):
            if message["type"] == "http.response.start":
                message["headers"] = list(message.get("headers", [])) + [
                    (b"cache-control", b"no-store"),
                    (b"x-content-type-options", b"nosniff"),
                    (b"referrer-policy", b"no-referrer"),
                    (
                        b"content-security-policy",
                        (
                            b"default-src 'self'; script-src 'self'; style-src 'self'; "
                            b"object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
                            b"form-action 'self'"
                            + (
                                b"; img-src 'self' data:; style-src-attr 'unsafe-inline'"
                                if scope.get("path") == "/docs"
                                else b""
                            )
                        ),
                    ),
                ]
            await send(message)

        await self.app(scope, buffered_receive, secured_send)


def create_app(*, settings: AppSettings | None = None, repository=None):
    settings = settings or AppSettings()
    repo = repository if repository is not None else HistoryRepository(settings)
    service = AnalysisService(repo, settings)

    @asynccontextmanager
    async def lifespan(app):
        yield
        await repo.close()

    app = FastAPI(
        title="PhishShield 郵件分析 API",
        description=DESCRIPTION,
        openapi_tags=TAGS,
        responses=COMMON_RESPONSES,
        version=PRODUCT_VERSION,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
    )
    register_documentation(app)
    app.state.repository, app.state.service = repo, service
    app.add_middleware(RequestBoundary, limit=settings.max_request_bytes)
    app.add_middleware(
        TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "testserver"]
    )

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request, exc):
        return error_response("INVALID_REQUEST", 422)

    @app.exception_handler(SQLAlchemyError)
    async def database_error(request, exc):
        return error_response("DATABASE_UNAVAILABLE", 503)

    @app.exception_handler(Exception)
    async def service_error(request, exc):
        return error_response("SERVICE_UNAVAILABLE", 503)

    @app.get("/api/v1/health", tags=["系統狀態"], summary="檢查服務與資料庫")
    async def health():
        """服務、資料庫與 migration 就緒時回 ready，資料庫不可用回 503。"""
        await repo.health()
        return dict(status="ready", database="ready", scope="local_poc")

    @app.get(
        "/api/v1/models/status",
        tags=["系統狀態"],
        summary="檢查 AI 與 A/B 模型可用性",
        response_model=ModelStatusResponse,
    )
    async def models_status():
        """唯讀查詢 endpoint/models，不推論。

        configuration_valid 表示連線設定有效；service_reachable 表示收到 HTTP 回覆。
        availability 為 available／missing／unconfirmed；connected 僅在 A/B ID 均存在時為 true。
        模型清單不支援或檢查失敗不會單獨禁止有效設定的 configured 分析。
        """
        return await model_status()

    @app.get("/api/v1/versions", tags=["系統狀態"], summary="取得產品發布狀態與診斷資訊")
    async def versions():
        return dict(
            product=PRODUCT_VERSION,
            api=API_VERSION,
            parser=PARSER_VERSION,
            ruleset=RULESET_VERSION,
            llm_pipeline=LLM_PIPELINE_VERSION,
            llm_schema=LLM_SCHEMA_VERSION,
            decision=DECISION_VERSION,
            database_schema=DATABASE_SCHEMA_VERSION,
            ui=UI_VERSION,
            evaluation=EVALUATION_VERSION,
            report=REPORT_VERSION,
        )

    def response(payload):
        status = 201
        if payload["status"] == "FAILED":
            phase = payload["failed_phase"]
            code = payload["errors"][0]["code"]
            status = 413 if code == "INPUT_TOO_LARGE" else (422 if phase == 1 else 503)
        return JSONResponse(payload, status_code=status)

    @app.post(
        "/api/v1/analyses",
        tags=["完整分析"],
        summary="分析貼上文字並保存",
        status_code=201,
        responses=ANALYSIS_RESPONSES,
    )
    async def analyze(request: Request, body: AnalyzeRequest):
        """JSON 提交 text 與 mode。fake 測試流程，configured 使用伺服器 AI 設定。"""
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            return error_response("UNSUPPORTED_MEDIA_TYPE", 415)
        return response(
            await service.analyze(body.text.encode("utf-8"), EmailSource.PASTED_TEXT, body.mode)
        )

    @app.post(
        "/api/v1/rules",
        tags=["規則預覽"],
        summary="預覽文字與初步規則訊號",
        responses={415: UNSUPPORTED_RESPONSE, 422: VALIDATION_RESPONSE},
    )
    async def preview(body: AnalyzeRequest):
        """回傳 preliminary、findings 與 source_document，無歷史寫入及模型呼叫。"""
        return await service.preview(body.text.encode("utf-8"), EmailSource.PASTED_TEXT)

    @app.post(
        "/api/v1/rules/file",
        tags=["規則預覽"],
        summary="預覽單封 EML 或 UTF-8 TXT",
        responses={415: UNSUPPORTED_RESPONSE, 422: VALIDATION_RESPONSE},
    )
    async def preview_file(
        file: Annotated[
            UploadFile, File(description="單封 .eml 或 UTF-8 .txt，最大 2,000,000 bytes。")
        ],
    ):
        """以 multipart/form-data 上傳 file，回原文與初步訊號，不保存歷史。"""
        try:
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in {".eml", ".txt"}:
                return error_response("UNSUPPORTED_FILE_TYPE", 415)
            raw = await file.read(2000001)
            if len(raw) > 2000000:
                return error_response("INPUT_TOO_LARGE", 413)
            source = EmailSource.EML_UPLOAD if suffix == ".eml" else EmailSource.PASTED_TEXT
            return await service.preview(raw, source)
        finally:
            await file.close()

    @app.post(
        "/api/v1/analyses/file",
        tags=["完整分析"],
        summary="分析單封 EML 或 UTF-8 TXT 並保存",
        status_code=201,
        responses=ANALYSIS_RESPONSES,
    )
    async def analyze_file(
        file: Annotated[
            UploadFile, File(description="單封 .eml 或 UTF-8 .txt，最大 2,000,000 bytes。")
        ],
        mode: Annotated[
            Literal["fake", "configured"],
            Form(description="configured 使用後端端點池；fake 僅供已啟用模擬的測試環境。"),
        ] = "configured",
    ):
        """multipart 包含 file 與 mode。批次逐封提交，每封獨立保存並回傳 analysis_id。"""
        try:
            suffix = Path(file.filename or "").suffix.lower()
            if suffix not in {".eml", ".txt"}:
                return error_response("UNSUPPORTED_FILE_TYPE", 415)
            raw = await file.read(2000001)
            if len(raw) > 2000000:
                return error_response("INPUT_TOO_LARGE", 413)
            source = EmailSource.EML_UPLOAD if suffix == ".eml" else EmailSource.PASTED_TEXT
            return response(await service.analyze(raw, source, mode))
        finally:
            await file.close()

    @app.get(
        "/api/v1/analyses",
        tags=["分析歷史"],
        summary="分頁取得歷史摘要",
        responses={422: VALIDATION_RESPONSE},
    )
    async def history(
        page: int = Query(1, ge=1, le=100000),
        page_size: int = Query(20, ge=1, le=100),
        query: str | None = Query(None, max_length=100),
        date_from: date | None = None,
        date_to: date | None = None,
    ):
        """以台北日期範圍及主旨、寄件者、內文、判斷摘要的不分大小寫片段搜尋。"""
        if date_from and date_to and date_from > date_to:
            return error_response("INVALID_DATE_RANGE", 422)
        filters = {
            key: value
            for key, value in {
                "query": query.strip() if query else None,
                "date_from": date_from,
                "date_to": date_to,
            }.items()
            if value
        }
        return await repo.list(page, page_size, **filters)

    async def report_response(identifiers, format):
        records = []
        for identifier in dict.fromkeys(identifiers):
            record = await repo.get(identifier)
            if record is None:
                return error_response("ANALYSIS_NOT_FOUND", 404)
            records.append(record)
        content = await asyncio.to_thread(export_reports, records, format)
        name = "phishshield-report" if len(records) == 1 else "phishshield-reports"
        return Response(
            content,
            media_type="application/pdf" if format == "pdf" else "application/zip",
            headers={"Content-Disposition": f'attachment; filename="{name}.{format}"'},
        )

    @app.post(
        "/api/v1/reports/export",
        tags=["報告匯出"],
        summary="批次匯出 PDF 或 ZIP",
        responses={
            200: {
                "content": {
                    "application/pdf": {"schema": {"type": "string", "format": "binary"}},
                    "application/zip": {"schema": {"type": "string", "format": "binary"}},
                }
            }
        },
        response_class=Response,
    )
    async def reports(body: ReportExportRequest):
        """提供 1–20 個已保存 analysis_id，format 為 pdf 或 zip。"""
        return await report_response(body.analysis_ids, body.format)

    @app.get(
        "/api/v1/analyses/{analysis_id}/report.pdf",
        tags=["報告匯出"],
        summary="下載單筆分析 PDF",
        responses={
            200: {
                "content": {
                    "application/pdf": {"schema": {"type": "string", "format": "binary"}},
                }
            }
        },
        response_class=Response,
    )
    async def report(analysis_id: UUID):
        """PDF 包含摘要、理由、必要執行狀態與原文證據節錄。"""
        return await report_response([analysis_id], "pdf")

    @app.get(
        "/api/v1/analyses/{analysis_id}",
        tags=["分析歷史"],
        summary="取得單筆原文、理由與證據",
        responses={
            200: {"content": {"application/json": {"schema": ANALYSIS_SCHEMA}}},
            404: {"description": "找不到該 analysis_id。"},
            422: VALIDATION_RESPONSE,
        },
    )
    async def detail(analysis_id: UUID):
        """analysis_id 為完整分析回傳的 UUID。舊紀錄的 source_document 可能為 null。"""
        result = await repo.get(analysis_id)
        return result if result is not None else error_response("ANALYSIS_NOT_FOUND", 404)

    app.mount("/", StaticFiles(directory=FRONTEND, html=True, check_dir=False), name="ui")
    return app
