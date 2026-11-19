# 檔案功能：提供雙模型命令列入口，串接解析、規則與模型分析並輸出受控結果。

import argparse
import asyncio
import sys

from pydantic import ValidationError
from pydantic_settings import SettingsError

from app.analysis.llm.pipeline import configured_pipeline, failure
from app.analysis.llm.settings import LLMSettings, fake_settings
from app.analysis.parser.limits import ParseLimits
from app.analysis.parser.result import parse_file_bytes_result, parse_file_result
from app.analysis.rules import RuleEngine
from app.domain.enums import EmailSource
from app.domain.stage_failure import StageFailure, stage_failure


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3 model recommendations; no final decision")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="Single .eml or UTF-8 .txt")
    source.add_argument("--paste", action="store_true", help="UTF-8 stdin")
    parser.add_argument("--fake", action="store_true", help="Explicit offline simulation")
    args = parser.parse_args()
    try:
        if args.file:
            email = parse_file_result(args.file)
        else:
            limits = ParseLimits()
            raw = sys.stdin.buffer.read(limits.max_input_bytes + 1)
            email = parse_file_bytes_result(raw, EmailSource.PASTED_TEXT, limits)
        rules = RuleEngine().analyze_result(email)
        if isinstance(rules, StageFailure):
            result = rules
        else:
            settings = LLMSettings()
            configured = configured_pipeline(fake_settings(settings) if args.fake else settings)
            result = (
                configured
                if isinstance(configured, StageFailure)
                else asyncio.run(configured.analyze_result(email, rules))
            )
    except OSError:
        result = stage_failure(1, "INPUT_READ_FAILED")
    except (ValidationError, SettingsError):
        result = failure("LLM_CONFIGURATION_INVALID")
    if isinstance(result, StageFailure):
        print(result.model_dump_json(indent=2), file=sys.stderr)
        return 1
    print(result.model_dump_json(indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
