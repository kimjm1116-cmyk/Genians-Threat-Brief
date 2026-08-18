from __future__ import annotations

from urllib.parse import parse_qs, urlparse

from src.sources import GLOBAL_DOMAINS, KR_DOMAINS

BLOCKED_HOSTS = (
    "news.google.com",
    "news.google.co.kr",
    "google.com",
    "google.co.kr",
    "consent.google.com",
)


def host_of(url: str) -> str:
    return urlparse(url).netloc.lower().removeprefix("www.")


def _matches(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def is_kr_domain(url: str) -> bool:
    host = host_of(url)
    return host.endswith(".kr") or _matches(host, KR_DOMAINS)


def is_global_domain(url: str) -> bool:
    return _matches(host_of(url), GLOBAL_DOMAINS)


def is_trusted_url(url: str, region: str | None = None) -> bool:
    if region == "kr":
        return is_kr_domain(url)
    if region == "global":
        return is_global_domain(url)
    return is_kr_domain(url) or is_global_domain(url)


def is_valid_article_url(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url.strip())
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.netloc or "." not in parsed.netloc:
        return False
    host = host_of(url)
    if any(host == b or host.endswith("." + b) for b in BLOCKED_HOSTS):
        return False
    if parsed.path.startswith("/url") and "q" in parse_qs(parsed.query):
        return False
    return is_trusted_url(url)
