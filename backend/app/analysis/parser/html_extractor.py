# 檔案功能：靜態擷取 HTML 正文、隱藏文字與連結，不執行腳本或載入遠端資源。

from dataclasses import dataclass

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

from app.analysis.parser.limits import ParseLimits, require_limit

NON_VISIBLE = {"script", "style", "template", "noscript", "head", "title"}
BLOCKS = {"p", "div", "br", "li", "tr", "h1", "h2", "h3", "section", "hr"}
ZERO_FONT_SIZES = {"0", "0px", "0pt", "0em", "0rem", "0%"}


def _inline_properties(tag: Tag) -> dict[str, str]:
    properties = {}
    for declaration in str(tag.get("style", "")).lower().split(";"):
        name, separator, value = declaration.partition(":")
        if separator:
            properties[name.strip()] = value.replace("!important", "").strip()
    return properties


def _hidden_container(tag: Tag, properties: dict[str, str]) -> bool:
    # Match complete property values; opacity:0.5 is visible, not opacity:0.
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


def is_hidden(tag: Tag) -> bool:
    properties = _inline_properties(tag)
    return (
        _hidden_container(tag, properties)
        or properties.get("font-size") in ZERO_FONT_SIZES
        or properties.get("color") == "transparent"
    )


def _text_is_hidden(node: NavigableString) -> bool:
    # Font/color inherit, so an explicit child style can override an ancestor's text style.
    # Container hiding still applies through every ancestor; this remains static CSS approximation.
    inherited = {}
    for parent in node.parents:
        properties = _inline_properties(parent)
        if _hidden_container(parent, properties):
            return True
        for name in ("font-size", "color"):
            if name not in inherited and properties.get(name) not in {None, "inherit", "unset"}:
                inherited[name] = properties[name]
    return inherited.get("font-size") in ZERO_FONT_SIZES or inherited.get("color") == "transparent"


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
            invisible = isinstance(node, Comment) or _text_is_hidden(node)
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
