# 檔案功能：提供離線規則命令列入口，串接郵件解析、規則選擇與失敗回報。

import argparse
import sys

from app.analysis.parser.limits import ParseLimits
from app.analysis.parser.result import parse_file_bytes_result, parse_file_result
from app.analysis.rules import RuleEngine
from app.domain.enums import EmailSource
from app.domain.stage_failure import StageFailure, stage_failure


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline rule signals; no final classification")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Single .eml or UTF-8 .txt")
    source.add_argument("--paste", action="store_true", help="UTF-8 stdin")
    parser.add_argument("--disable", action="append", default=[], metavar="RULE_ID")
    args = parser.parse_args()
    try:
        default = RuleEngine()
        if set(args.disable) - set(default.rule_versions):
            print(stage_failure(2, "UNKNOWN_RULE_ID").model_dump_json(indent=2), file=sys.stderr)
            return 1
        engine = RuleEngine(
            enabled_ids=[key for key in default.rule_versions if key not in args.disable]
        )
        if args.file:
            email = parse_file_result(args.file)
        else:
            limits = ParseLimits()
            raw = sys.stdin.buffer.read(limits.max_input_bytes + 1)
            email = parse_file_bytes_result(raw, EmailSource.PASTED_TEXT, limits)
        result = engine.analyze_result(email)
    except OSError:
        result = stage_failure(1, "INPUT_READ_FAILED")
    if isinstance(result, StageFailure):
        print(result.model_dump_json(indent=2), file=sys.stderr)
        return 1
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
