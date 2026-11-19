# 檔案功能：靜態擷取 HTML 正文、隱藏文字與連結，不執行腳本或載入遠端資源。

from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from app.analysis.parser.limits import ParseLimits, require_limit

NON_VISIBLE = {"script", "style", "template", "noscript", "head", "title"}
BLOCKS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "section", "hr"}


def is_hidden(tag: Tag) -> bool:
    # Match complete property values; opacity:0.5 is visible, not opacity:0.
    properties = {}
    for declaration in str(tag.get("style", "")).lower().split(";"):
        name, separator, value = declaration.partition(":")
        if separator:
            properties[name.strip()] = value.replace("!important", "").strip()
    try:
        transparent = float(properties.get("opacity", "1").removesuffix("%")) == 0
    except ValueError:
        transparent = False
    return (
        tag.name in NON_VISIBLE
        or tag.has_attr("hidden")
        or str(tag.get("aria-hidden", "")).lower() == "true"
        or properties.get("display") == "none"
        or properties.get("visibility") in {"hidden", "collapse"}
        or transparent
    )


@dataclass
class HTMLContent:
    visible_text: str
    hidden_texts: list[str]
    links: list[tuple[str, str, str]]


def extract_html(html: str, location: str, limits: ParseLimits) -> HTMLContent:
    # html.parser does not execute scripts, resolve CSS, or fetch remote resources.
    soup = BeautifulSoup(html, "html.parser")
    visible: list[str] = []
    hidden: list[str] = []
    links: list[tuple[str, str, str]] = []
    for node in soup.descendants:
        if isinstance(node, Tag):
            if node.name == "a" and node.has_attr("href"):
                links.append((str(node["href"]), node.get_text(), location))
                require_limit(
                    len(links),
                    min(
                        limits.max_urls,
                        limits.max_html_anchor_occurrences,
                        limits.max_url_scan_occurrences,
                    ),
                    "URL_LIMIT_EXCEEDED",
                    metric="html_anchor_occurrences",
                )
            if node.name in BLOCKS:
                visible.append("\n")
        elif isinstance(node, NavigableString):
            text = str(node)
            invisible = isinstance(node, Comment) or any(is_hidden(p) for p in node.parents)
            if invisible:
                if text.strip():
                    hidden.append(text.strip())
            else:
                visible.append(text)
    require_limit(
        sum(map(len, visible)) + sum(map(len, hidden)),
        limits.max_text_chars,
        "TEXT_LIMIT_EXCEEDED",
    )
    return HTMLContent("".join(visible), hidden, links)
