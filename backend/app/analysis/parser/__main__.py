# 檔案功能：提供郵件解析命令列入口，處理檔案或標準輸入並輸出解析結果。

import argparse
import sys

from app.analysis.parser.limits import ParseLimits
from app.analysis.parser.result import parse_file_bytes_result, parse_file_result
from app.domain.enums import EmailSource
from app.domain.stage_failure import StageFailure, stage_failure


def main() -> int:
    argument_parser = argparse.ArgumentParser(
        description="Supported files: .eml (single email), .txt (UTF-8 text). No threat verdict.",
        epilog="Unsupported: .msg, .mbox, .html, PDF, Office, images, archives. "
        "Attachments: metadata only. Default input limit: 2,000,000 bytes.",
    )
    source = argument_parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", metavar="PATH", help="Read .eml or UTF-8 .txt by extension")
    source.add_argument("--eml", metavar="PATH", help="Read a single .eml email only")
    source.add_argument("--txt", metavar="PATH", help="Read a UTF-8 .txt file (optional UTF-8 BOM)")
    source.add_argument("--paste", action="store_true", help="Read literal UTF-8 text from stdin")
    args = argument_parser.parse_args()
    limits = ParseLimits()
    try:
        if args.file or args.eml or args.txt:
            expected = ".eml" if args.eml else ".txt" if args.txt else None
            email = parse_file_result(
                args.file or args.eml or args.txt, limits, expected_extension=expected
            )
        else:
            raw = sys.stdin.buffer.read(limits.max_input_bytes + 1)
            kind = EmailSource.PASTED_TEXT
            email = parse_file_bytes_result(raw, kind, limits)
    except OSError:
        email = stage_failure(1, "INPUT_READ_FAILED")
    if isinstance(email, StageFailure):
        print(email.model_dump_json(indent=2), file=sys.stderr)
        return 1
    print(email.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
