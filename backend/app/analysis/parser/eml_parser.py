# 檔案功能：解析單封 MIME 郵件，透過隔離程序限制資源與逾時並保留證據。

import hashlib
import multiprocessing
from concurrent.futures import ThreadPoolExecutor
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses
from time import monotonic

from app.analysis.parser.async_execution import cancellation_requested
from app.analysis.parser.decoding import decode_bytes
from app.analysis.parser.html_extractor import extract_html
from app.analysis.parser.limits import ParseError, ParseLimits, require_limit
from app.analysis.parser.normalizer import (
    analysis_view,
    normalize_address,
    normalize_text,
    unicode_signals,
)
from app.analysis.parser.review import build_review_items
from app.analysis.parser.url_extractor import URLCollector
from app.domain.email_models import AttachmentMetadata, NormalizedEmail
from app.domain.enums import EmailSource
from app.domain.reliability_models import HeaderProfile

HEADERS = {
    "from",
    "reply-to",
    "to",
    "cc",
    "subject",
    "authentication-results",
    "received-spf",
    "dkim-signature",
}


def _check_structure(message: Message, limits: ParseLimits) -> HeaderProfile:
    # Check the entire MIME tree, including opaque forwarded-message attachments.
    pending = [(message, 0)]
    count = header_chars = 0
    maximum_depth = 0
    totals = {
        key: {"category": key, "fields": 0, "chars": 0, "serialized_bytes": 0}
        for key in ("authentication", "routing", "mime", "other")
    }

    def profile(status):
        return HeaderProfile(
            status=status,
            parts_examined=count,
            maximum_depth=maximum_depth,
            categories=list(totals.values()),
        )

    while pending:
        part, depth = pending.pop()
        count += 1
        require_limit(count, limits.max_mime_parts, "MIME_PART_LIMIT_EXCEEDED")
        require_limit(depth, limits.max_mime_depth, "MIME_DEPTH_LIMIT_EXCEEDED")
        maximum_depth = max(maximum_depth, depth)
        for key, value in part.raw_items():
            name = key.lower()
            category = (
                "authentication"
                if name in {"authentication-results", "received-spf", "dkim-signature"}
                or name.startswith("arc-")
                else "routing"
                if name
                in {
                    "received",
                    "from",
                    "to",
                    "cc",
                    "reply-to",
                    "return-path",
                    "date",
                    "message-id",
                    "subject",
                }
                else "mime"
                if name.startswith("content-") or name == "mime-version"
                else "other"
            )
            size = len(key) + len(value)
            header_chars += size
            totals[category]["fields"] += 1
            totals[category]["chars"] += size
            totals[category]["serialized_bytes"] += len(
                (key + value).encode("utf-8", "surrogatepass")
            )
        try:
            require_limit(header_chars, limits.max_header_chars, "HEADER_LIMIT_EXCEEDED")
        except ParseError as exc:
            exc.resource.header_profile = profile("bounded_prefix")
            raise
        if part.is_multipart():
            pending.extend((child, depth + 1) for child in reversed(part.get_payload()))
    return profile("complete")


def _decode(part: Message, warnings: list[str]) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        value = part.get_payload()
        return value if isinstance(value, str) else ""
    return decode_bytes(payload, part.get_content_charset(), warnings)


def _parse(raw: bytes, source: EmailSource, limits: ParseLimits) -> NormalizedEmail:
    warnings: list[str] = []
    email = NormalizedEmail(source=source, content_hash=hashlib.sha256(raw).hexdigest())
    bodies: list[str] = []
    html_links: list[tuple[str, str, str]] = []
    if source == EmailSource.PASTED_TEXT:
        try:
            bodies.append(raw.decode("utf-8"))
        except UnicodeError as exc:
            raise ParseError("INVALID_TEXT_ENCODING") from exc
    else:
        message = BytesParser(policy=policy.default).parsebytes(raw)
        email.resource_profile = _check_structure(message, limits)

        def walk(part: Message, depth: int, location: str) -> None:
            if part.defects:
                warnings.append("MALFORMED_MIME")
            disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            body_part = content_type in {"text/plain", "text/html"} or (
                part.get_content_maintype() == "multipart"
            )
            filename = part.get_filename()
            opaque = disposition == "attachment" or (filename is not None and not body_part)
            # A named body remains both readable content and file metadata.
            if disposition == "attachment" or filename is not None:
                if opaque and disposition != "attachment":
                    warnings.append("UNSUPPORTED_INLINE_CONTENT")
                require_limit(
                    len(email.attachments_metadata) + 1,
                    limits.max_attachments,
                    "ATTACHMENT_LIMIT_EXCEEDED",
                )
                data = part.get_payload(decode=True)
                # Nested message attachments remain opaque and are never analyzed/executed.
                if data is None:
                    data = part.as_bytes(policy=policy.default)
                email.attachments_metadata.append(
                    AttachmentMetadata(
                        filename=filename,
                        content_type=part.get_content_type(),
                        size_bytes=len(data),
                    )
                )
                if opaque:
                    return
            if part.is_multipart():
                for index, child in enumerate(part.get_payload()):
                    walk(child, depth + 1, f"{location}.{index}")
                return
            if content_type in {"text/plain", "text/html"}:
                text = _decode(part, warnings)
                require_limit(len(text), limits.max_text_chars, "TEXT_LIMIT_EXCEEDED")
                if content_type == "text/html":
                    warnings.append("HTML_VISIBILITY_APPROXIMATE")
                    extracted = extract_html(text, location, limits)
                    bodies.append(extracted.visible_text)
                    email.hidden_texts.extend(extracted.hidden_texts)
                    html_links.extend(extracted.links)
                else:
                    bodies.append(text)
            else:
                warnings.append("UNSUPPORTED_INLINE_CONTENT")
            # Decoding may add base64/transfer-encoding defects.
            if part.defects:
                warnings.append("MALFORMED_MIME")

        walk(message, 0, "mime:0")
        for key in sorted(HEADERS):
            values = message.get_all(key, [])
            if values:
                email.headers[key] = [str(value) for value in values]
                if any(getattr(value, "defects", ()) for value in values):
                    warnings.append("MALFORMED_HEADER")

        def addresses(key: str) -> list[str]:
            return [
                normalize_address(addr)
                for _, addr in getaddresses(email.headers.get(key, []))
                if addr
            ]

        senders = addresses("from")
        replies = addresses("reply-to")
        if len(senders) > 1:
            warnings.append("MULTIPLE_SENDERS")
        email.sender = senders[0] if senders else None
        email.reply_to = replies[0] if replies else None
        email.recipients = addresses("to") + addresses("cc")
        email.subject = (email.headers.get("subject") or [None])[0]
    email.body_text = normalize_text("\n".join(bodies))
    require_limit(
        len(email.body_text) + sum(map(len, email.hidden_texts)),
        limits.max_text_chars,
        "TEXT_LIMIT_EXCEEDED",
    )
    body_view = analysis_view(email.body_text)
    email.body_analysis_text = body_view.text
    email.hidden_analysis_texts = [analysis_view(text).text for text in email.hidden_texts]
    email.analysis_headers = {
        key: [analysis_view(value).text for value in values]
        for key, values in email.headers.items()
    }
    require_limit(
        sum(len(value) for values in email.analysis_headers.values() for value in values),
        limits.max_header_chars,
        "HEADER_LIMIT_EXCEEDED",
    )
    require_limit(
        len(email.body_analysis_text) + sum(map(len, email.hidden_analysis_texts)),
        limits.max_text_chars,
        "TEXT_LIMIT_EXCEEDED",
    )
    collector = URLCollector(limits)
    for link in html_links:
        collector.add_html(*link)
    collector.add_text(email.body_text, "body")
    for index, hidden in enumerate(email.hidden_texts):
        collector.add_text(hidden, f"hidden:{index}")
    email.urls = collector.urls
    if any(url.boundary_ambiguous for url in email.urls):
        warnings.append("URL_BOUNDARY_AMBIGUOUS")
    if any(
        any(label.startswith("xn--") for label in (url.hostname or "").split("."))
        for url in email.urls
    ):
        warnings.append("INTERNATIONALIZED_DOMAIN")
    texts = [
        email.body_text,
        *email.hidden_texts,
        *(value for values in email.headers.values() for value in values),
        *(url.href + " " + url.display_text for url in email.urls),
        *(item.filename or "" for item in email.attachments_metadata),
    ]
    for text in texts:
        warnings.extend(unicode_signals(text))
    for key, value in (("SENDER", email.sender), ("SUBJECT", email.subject)):
        if value is None:
            warnings.append(f"MISSING_{key}")
    if not email.body_text:
        warnings.append("EMPTY_BODY")
    if email.hidden_texts:
        warnings.append("HIDDEN_CONTENT_PRESENT")
    if any(
        name in email.headers
        for name in ("authentication-results", "received-spf", "dkim-signature")
    ):
        warnings.append("UNTRUSTED_AUTH_HEADERS")
    if any(url.parse_warning for url in email.urls):
        warnings.append("URL_PARSE_WARNING")
    email.parse_warnings = sorted(set(warnings))
    email.review_items = build_review_items(email)
    # Revalidate after building; no raw HTML/attachment bytes appear in the output.
    return NormalizedEmail.model_validate(email.model_dump(exclude_computed_fields=True))


def _worker(connection, raw: bytes, source: EmailSource, limits: ParseLimits) -> None:
    try:
        connection.send(
            (
                "ok",
                _parse(raw, source, limits).model_dump(mode="json", exclude_computed_fields=True),
            )
        )
    except ParseError as exc:
        connection.send(
            (
                "error",
                {
                    "code": exc.code,
                    "resource": exc.resource.model_dump(mode="json") if exc.resource else None,
                },
            )
        )
    except Exception:
        # Never leak raw email, parser traceback, or local filesystem paths.
        connection.send(("error", "PARSE_FAILED"))
    finally:
        connection.close()


def _run_isolated(raw: bytes, source: EmailSource, limits: ParseLimits) -> NormalizedEmail:
    if not isinstance(raw, bytes):
        raise ParseError("INVALID_INPUT_TYPE")
    require_limit(len(raw), limits.max_input_bytes, "INPUT_TOO_LARGE")
    if not raw.strip():
        raise ParseError("EMPTY_INPUT")
    if cancellation_requested():
        raise ParseError("PARSE_TIMEOUT")
    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(send, raw, source, limits), daemon=True)
    started = False
    reader = None
    try:
        process.start()
        started = True
        send.close()
        reader = ThreadPoolExecutor(max_workers=1, thread_name_prefix="parser-result")
        try:
            # Read the complete result under the deadline, not just its first byte.
            result = reader.submit(receive.recv)
            deadline = monotonic() + limits.timeout_seconds
            while True:
                if cancellation_requested() or monotonic() >= deadline:
                    raise TimeoutError
                try:
                    state, payload = result.result(
                        timeout=max(0, min(0.025, deadline - monotonic()))
                    )
                    break
                except TimeoutError:
                    if result.done():
                        raise
        except TimeoutError as exc:
            raise ParseError("PARSE_TIMEOUT") from exc
        except EOFError as exc:
            raise ParseError("PARSE_FAILED") from exc
        if state == "error":
            if isinstance(payload, dict):
                from app.domain.reliability_models import ResourceDiagnostic

                raise ParseError(
                    payload["code"],
                    ResourceDiagnostic.model_validate(payload["resource"])
                    if payload["resource"]
                    else None,
                )
            raise ParseError(payload)
        return NormalizedEmail.model_validate(payload)
    finally:
        send.close()
        if started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=0.5)
            if process.is_alive():
                process.kill()
                process.join()
            process.close()
        if reader is not None:
            reader.shutdown(wait=True)
        receive.close()


def parse_eml(raw: bytes, limits: ParseLimits | None = None) -> NormalizedEmail:
    """Parse an EML under size and wall-clock limits. No external resources are read."""
    return _run_isolated(raw, EmailSource.EML_UPLOAD, limits or ParseLimits())
