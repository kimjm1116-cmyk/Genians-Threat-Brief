from __future__ import annotations

import hashlib
import logging
import re
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from typing import Iterable
from urllib.parse import parse_qs, urlparse

import feedparser
import httpx
from bs4 import BeautifulSoup

from src.config import settings
from src.links import is_trusted_url, is_valid_article_url
from src.models import Article
from src.sources import GLOBAL_RSS_FEEDS, INCIDENT_KEYWORDS, KR_RSS_FEEDS

logger = logging.getLogger(__name__)

_TAG_RE = re.compile(r"<[^>]+>")


def is_incident_text(title: str, summary: str) -> bool:
    blob = f"{title} {summary}".lower()
    return any(k in blob for k in INCIDENT_KEYWORDS)


def _strip_html(text: str) -> str:
    return re.sub(r"\s+", " ", _TAG_RE.sub(" ", text or "")).strip()


def _unwrap_google_news(entry, fallback: str) -> str:
    html = getattr(entry, "summary", "") or getattr(entry, "description", "") or ""
    soup = BeautifulSoup(html, "lxml")
    for anchor in soup.find_all("a", href=True):
        href = anchor["href"].strip()
        if is_valid_article_url(href) or is_trusted_url(href):
            return href
    parsed = urlparse(fallback)
    qs = parse_qs(parsed.query)
    if "url" in qs and is_trusted_url(qs["url"][0]):
        return qs["url"][0]
    return fallback


def _article_id(title: str, url: str) -> str:
    key = f"{title.strip().lower()}|{url.strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _parse_published(entry) -> datetime | None:
    for parsed in (
        getattr(entry, "published_parsed", None),
        getattr(entry, "updated_parsed", None),
    ):
        if parsed:
            try:
                return datetime(*parsed[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                continue
    for raw in (
        getattr(entry, "published", None),
        getattr(entry, "updated", None),
        getattr(entry, "pubDate", None),
    ):
        if not raw:
            continue
        try:
            dt = parsedate_to_datetime(str(raw))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except (TypeError, ValueError, OverflowError):
            continue
    return None


def _is_fresh(published: datetime | None, cutoff: datetime) -> bool:
    if published is None:
        return False
    if published.tzinfo is None:
        published = published.replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc) + timedelta(minutes=30)
    return cutoff <= published <= now


def _parse_entry(source: str, entry, region: str) -> Article | None:
    title = _strip_html(getattr(entry, "title", "") or "")
    raw_link = (getattr(entry, "link", "") or "").strip()
    if not title or not raw_link:
        return None

    url = _unwrap_google_news(entry, raw_link) if "news.google.com" in raw_link else raw_link
    url = url.split("#")[0]
    if not is_valid_article_url(url):
        return None
    if region == "kr" and not is_trusted_url(url, "kr") and not urlparse(url).netloc.lower().endswith(".kr"):
        return None
    if region == "global" and not is_trusted_url(url, "global"):
        return None

    published = _parse_published(entry)
    summary = _strip_html(getattr(entry, "summary", "") or getattr(entry, "description", "") or "")
    if not is_incident_text(title, summary):
        return None

    lang = "ko" if region == "kr" else "en"
    resolved_region = "kr" if is_trusted_url(url, "kr") or urlparse(url).netloc.lower().endswith(".kr") else "global"
    if region in ("kr", "global"):
        resolved_region = region
    return Article(
        title=title,
        url=url,
        source=source,
        published_at=published,
        summary_raw=summary[:1200],
        language=lang,
        region=resolved_region,
    )


def _fetch_feeds(
    feeds: list[tuple[str, str]],
    region: str,
    cutoff: datetime,
) -> list[Article]:
    articles: list[Article] = []
    headers = {"User-Agent": settings.user_agent}
    with httpx.Client(timeout=settings.http_timeout, headers=headers, follow_redirects=True) as client:
        for source, url in feeds:
            try:
                resp = client.get(url)
                resp.raise_for_status()
                feed = feedparser.parse(resp.content)
                for entry in feed.entries:
                    item = _parse_entry(source, entry, region)
                    if item and _is_fresh(item.published_at, cutoff):
                        articles.append(item)
            except Exception:
                logger.exception("RSS 수집 실패: %s", source)
    return articles


def fetch_newsapi_articles(cutoff: datetime) -> list[Article]:
    if not settings.newsapi_key:
        return []

    params = {
        "q": "ransomware OR data breach OR cyber attack OR APT OR malware",
        "language": "en",
        "sortBy": "publishedAt",
        "pageSize": 50,
        "from": cutoff.isoformat(),
        "apiKey": settings.newsapi_key,
    }
    try:
        with httpx.Client(timeout=settings.http_timeout) as client:
            resp = client.get("https://newsapi.org/v2/everything", params=params)
            resp.raise_for_status()
            data = resp.json()
    except Exception:
        logger.exception("NewsAPI 수집 실패")
        return []

    items: list[Article] = []
    for raw in data.get("articles", []):
        title = (raw.get("title") or "").strip()
        url = (raw.get("url") or "").strip()
        summary = (raw.get("description") or "")[:1200]
        if not title or not url or title == "[Removed]" or not is_valid_article_url(url):
            continue
        if not is_incident_text(title, summary):
            continue
        published = None
        if raw.get("publishedAt"):
            try:
                published = datetime.fromisoformat(raw["publishedAt"].replace("Z", "+00:00"))
            except ValueError:
                published = None
        if published is None or not _is_fresh(published, cutoff):
            continue
        items.append(
            Article(
                title=title,
                url=url,
                source=(raw.get("source") or {}).get("name") or "NewsAPI",
                published_at=published,
                summary_raw=summary,
                region="global",
            )
        )
    return items


def dedupe(articles: Iterable[Article]) -> list[Article]:
    seen: set[str] = set()
    unique: list[Article] = []
    for article in articles:
        aid = _article_id(article.title, article.url)
        if aid in seen:
            continue
        seen.add(aid)
        unique.append(article)
    return unique


def collect_articles(exclude_urls: set[str] | None = None) -> list[Article]:
    cutoff = datetime.now(timezone.utc) - timedelta(hours=settings.lookback_hours)
    blocked = {(u or "").strip().rstrip("/").lower() for u in (exclude_urls or set()) if u}
    pooled = (
        _fetch_feeds(KR_RSS_FEEDS, "kr", cutoff)
        + _fetch_feeds(GLOBAL_RSS_FEEDS, "global", cutoff)
        + fetch_newsapi_articles(cutoff)
    )
    unique = dedupe(pooled)
    if blocked:
        unique = [a for a in unique if a.url.strip().rstrip("/").lower() not in blocked]
    unique.sort(key=lambda a: a.published_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    logger.info(
        "수집 %s건 / 필터 후 %s건 (국내 %s, 해외 %s)",
        len(pooled),
        len(unique),
        sum(1 for a in unique if a.region == "kr"),
        sum(1 for a in unique if a.region == "global"),
    )
    return unique[: settings.max_collected_articles]
