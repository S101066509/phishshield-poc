# 檔案功能：定義統一郵件、網址、附件中繼資料及人工覆核等共同資料契約。

from pydantic import BaseModel, ConfigDict, Field, computed_field

from app.domain.enums import EmailSource
from app.domain.reliability_models import HeaderProfile
from app.domain.versions import PARSER_VERSION


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid")


class URLFinding(Contract):
    href: str
    normalized_url: str | None = None
    hostname: str | None = None
    display_text: str = ""
    source_location: str
    parse_warning: str | None = None
    analysis_url: str | None = None
    raw_candidate: str | None = None
    raw_source_location: str | None = None
    boundary_reasons: list[str] = Field(default_factory=list)

    @computed_field
    @property
    def boundary_ambiguous(self) -> bool:
        return bool(self.boundary_reasons)


class ReviewItem(Contract):
    code: str
    message: str
    evidence_refs: list[str] = Field(default_factory=list)


class AttachmentMetadata(Contract):
    filename: str | None = None
    content_type: str
    size_bytes: int = Field(ge=0)


class AuthResults(Contract):
    # Uploaded/pasted headers are self-asserted, never trusted authentication.
    source_trusted: bool = False
    verification: str = "unknown"


class NormalizedEmail(Contract):
    source: EmailSource
    sender: str | None = None
    reply_to: str | None = None
    recipients: list[str] = Field(default_factory=list)
    subject: str | None = None
    body_text: str = ""
    body_analysis_text: str = ""
    hidden_analysis_texts: list[str] = Field(default_factory=list)
    analysis_headers: dict[str, list[str]] = Field(default_factory=dict)
    urls: list[URLFinding] = Field(default_factory=list)
    headers: dict[str, list[str]] = Field(default_factory=dict)
    auth_results: AuthResults = Field(default_factory=AuthResults)
    attachments_metadata: list[AttachmentMetadata] = Field(default_factory=list)
    hidden_texts: list[str] = Field(default_factory=list)
    parse_warnings: list[str] = Field(default_factory=list)
    review_items: list[ReviewItem] = Field(default_factory=list)
    content_hash: str = Field(pattern=r"^[a-f0-9]{64}$")
    parser_version: str = PARSER_VERSION
    resource_profile: HeaderProfile | None = None

    @computed_field
    @property
    def review_required(self) -> bool:
        return bool(self.review_items)
