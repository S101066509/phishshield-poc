# 檔案功能：定義規則階段輸出，保存版本、命中訊號與人工覆核資訊。

from pydantic import computed_field

from app.domain.analysis_models import RuleFinding
from app.domain.email_models import Contract, ReviewItem


class RuleRun(Contract):
    parser_version: str
    ruleset_version: str
    rule_versions: dict[str, str]
    content_hash: str
    findings: list[RuleFinding]
    review_items: list[ReviewItem]

    @computed_field
    @property
    def review_required(self) -> bool:
        return bool(self.review_items)
