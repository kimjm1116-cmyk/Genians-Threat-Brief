"""국내외 사이버 위협 현황 자동화 봇.

Ransomware.live + 보안 뉴스 RSS + Twitter(RSSHub)를 수집하고,
GPT-4o JSON을 정렬 가능한 하이퍼링크 HTML 표로 만든 뒤 Slack에 업로드한다.
"""

from __future__ import annotations

import html
import json
import os
import re
import sys
import subprocess
import traceback
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import feedparser
import requests
from dotenv import load_dotenv
from openai import OpenAI
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o").strip() or "gpt-4o"
SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN", "").strip()
SLACK_CHANNEL_ID = os.getenv("SLACK_CHANNEL_ID", "").strip()
GITHUB_PAGES_URL = os.getenv(
    "GITHUB_PAGES_URL",
    # 예: https://{깃허브아이디}.github.io/{저장소이름}/
    "",
).strip()

LOOKBACK_HOURS = 24
KST = timezone(timedelta(hours=9))
HTTP_TIMEOUT = 25
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,application/rss+xml,application/json;q=0.8,*/*;q=0.7",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
}
RANSOMWARE_LIVE_HOME = "https://www.ransomware.live/"

RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims"
RSS_FEEDS = (
    ("BleepingComputer", "https://www.bleepingcomputer.com/feed/"),
    ("The Hacker News", "https://feeds.feedburner.com/TheHackersNews"),
    ("Dark Reading", "https://www.darkreading.com/rss.xml"),
    ("The Record", "https://therecord.media/feed/"),
    ("CyberScoop", "https://www.cyberscoop.com/feed/"),
    ("SecurityWeek", "https://www.securityweek.com/feed/"),
    ("보안뉴스", "https://www.boannews.com/media/news_rss.xml"),
    ("데일리시큐", "https://www.dailysecu.com/rss/allArticle.xml"),
)
TWITTER_ACCOUNTS = (
    "GossiTheDog",
    "TheDFIRReport",
    "BleepinComputer",
    "vxunderground",
    "sans_isc",
    "briankrebs",
)
RSSHUB_TEMPLATES = (
    "https://rsshub.app/twitter/user/{handle}",
    "https://rsshub.rssforever.com/twitter/user/{handle}",
)

COLUMNS = ("위협 일자", "기업/기관", "국가", "산업군", "사고 유형", "공격그룹", "공격기법", "피해 내용", "신뢰도")
COLUMN_ALIASES = {
    "date": "위협 일자",
    "discovered": "위협 일자",
    "published": "위협 일자",
    "company": "기업/기관",
    "source_url": "출처_URL",
    "url": "출처_URL",
    "country": "국가",
    "industry": "산업군",
    "type": "사고 유형",
    "incident_type": "사고 유형",
    "group": "공격그룹",
    "technique": "공격기법",
    "damage": "피해 내용",
    "reliability": "신뢰도",
}

COUNTRY_KO = {
    "US": "미국", "KR": "한국", "JP": "일본", "CN": "중국", "GB": "영국", "UK": "영국",
    "DE": "독일", "FR": "프랑스", "IT": "이탈리아", "ES": "스페인", "NL": "네덜란드",
    "BE": "벨기에", "CH": "스위스", "AT": "오스트리아", "SE": "스웨덴", "NO": "노르웨이",
    "DK": "덴마크", "FI": "핀란드", "PL": "폴란드", "CZ": "체코", "AU": "호주",
    "NZ": "뉴질랜드", "CA": "캐나다", "MX": "멕시코", "BR": "브라질", "AR": "아르헨티나",
    "CL": "칠레", "IN": "인도", "SG": "싱가포르", "MY": "말레이시아", "TH": "태국",
    "VN": "베트남", "PH": "필리핀", "ID": "인도네시아", "TW": "대만", "HK": "홍콩",
    "AE": "아랍에미리트", "SA": "사우디아라비아", "IL": "이스라엘", "TR": "튀르키예",
    "ZA": "남아프리카공화국", "EG": "이집트", "RU": "러시아", "UA": "우크라이나",
    "IE": "아일랜드", "PT": "포르투갈", "GR": "그리스", "RO": "루마니아", "HU": "헝가리",
    "AL": "알바니아", "MA": "모로코",
}

INDUSTRY_KO = {
    "financial services": "금융",
    "finance": "금융",
    "banking": "금융",
    "retail & e-commerce": "유통",
    "retail": "유통",
    "e-commerce": "유통",
    "manufacturing": "제조",
    "technology": "IT",
    "it": "IT",
    "software": "IT",
    "education": "교육",
    "government & defense": "공공",
    "government": "공공",
    "defense": "공공",
    "healthcare": "의료",
    "health": "의료",
    "hospitality": "숙박/외식",
    "professional services": "전문서비스",
    "transportation": "물류",
    "logistics": "물류",
    "agriculture and food production": "농식품",
    "agriculture": "농식품",
    "food": "농식품",
    "construction": "건설",
    "energy": "에너지",
    "telecom": "통신",
    "telecommunications": "통신",
    "media": "미디어",
    "legal": "법률",
    "insurance": "보험",
    "not found": "미상",
    "other": "미상",
    "n/a": "미상",
}

COUNTRY_ISO_BY_NAME = {name: code.lower() for code, name in COUNTRY_KO.items()}
COUNTRY_ISO_BY_NAME["영국"] = "gb"
FLAG_RE = re.compile(r"[\U0001F1E6-\U0001F1FF]{2}")

SYSTEM_PROMPT = """당신은 최고 수준의 CTI 분석가입니다. 뉴스 및 트위터 데이터를 종합 분석하여 다음 JSON 스키마에 맞게 결과를 출력하세요. 중요한 위협 정보는 절대 누락하지 마세요.
랜섬웨어 API, 보안 뉴스 RSS, 트위터 인텔리전스를 골고루 반영하세요.
트위터는 침해사고·랜섬웨어·취약점·악성코드 등 의미 있는 위협만 포함하고, 단순 잡담은 제외하세요.

{
  "threats": [
    {
      "위협 일자": "사고 발견/보도 날짜 (YYYY-MM-DD)",
      "기업/기관": "피해 기업/기관명. 취약점 공지·CVE·제품 결함 경고이면 '취약점 공지'. 침해사고인데 회사명을 특정할 수 없으면 '확인필요'. '해당없음'은 쓰지 마세요.",
      "출처_URL": "해당 정보가 추출된 원문 기사 링크 또는 제공된 관련 URL",
      "국가": "ISO 국가코드와 한국어명 (예: US 미국, KR 한국. 모르면 '미상')",
      "산업군": "반드시 한국어 대표 산업군 (제조, 금융, 의료, 교육, 공공, IT, 유통 등. 모르면 '미상')",
      "사고 유형": "랜섬웨어, 정보유출, 제로데이, 악성코드 유포 등",
      "공격그룹": "해킹 그룹명 (예: LockBit, 미상)",
      "공격기법": "파악 가능한 공격 흐름 (모르면 '미상')",
      "피해 내용": "데이터 유출, 시스템 암호화 등 요약",
      "신뢰도": "🔴 확인, 🟠 조사중, 🟡 공격자 주장"
    }
  ]
}
추출할 데이터가 없다면 빈 배열을 반환하세요.
같은 기업·같은 사건은 한 건만 남기세요.
중요도가 높은 사고를 우선하고, 최대 30건까지 포함하세요.
Ransomware.live 항목의 사고 유형은 무조건 '랜섬웨어', 신뢰도는 무조건 '🔴 확인'입니다.
산업군은 영어 원문을 한국어로 번역하세요. (Financial Services→금융, Manufacturing→제조, Technology→IT 등)
국가 값은 'US 미국'처럼 ISO 코드 + 한국어명을 함께 적으세요. 이모지만 쓰지 마세요.
위협 일자는 입력의 날짜/발견시각을 YYYY-MM-DD로 적으세요.
출처_URL은 입력 텍스트에 명시된 원문 링크를 그대로 사용하세요. 임의로 만들지 마세요.
기업/기관 작성 규칙:
- 피해 기업/기관이 명확하면 그 이름을 적으세요.
- GitLab/워드프레스 플러그인/OS 결함처럼 취약점 공지·패치 권고이면 '취약점 공지'.
- 유출·랜섬웨어 등 침해사고인데 회사명을 고를 수 없으면 '확인필요'.
- '해당없음'은 사용하지 마세요.
"""

TAG_RE = re.compile(r"<[^>]+>")
EMPTY_MESSAGE = "새로운 위협 동향이 없습니다."


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def today_label() -> str:
    return now_utc().astimezone(KST).strftime("%Y년 %m월 %d일")


def html_filename(date_label: str | None = None) -> str:
    # GitHub Pages로 고정 배포하므로 파일명은 항상 index.html
    return "index.html"


def html_path(date_label: str | None = None) -> Path:
    public_dir = ROOT_DIR / "public"
    return public_dir / "index.html"


def cutoff_utc() -> datetime:
    return now_utc() - timedelta(hours=LOOKBACK_HOURS)


def parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)

    text = str(value).strip()
    if not text:
        return None
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        pass
    try:
        dt = parsedate_to_datetime(text)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def is_within_24h(dt: datetime | None, cutoff: datetime) -> bool:
    if dt is None:
        return False
    return cutoff <= dt <= now_utc() + timedelta(minutes=10)


def strip_html(text: str) -> str:
    cleaned = TAG_RE.sub(" ", html.unescape(text or ""))
    return re.sub(r"\s+", " ", cleaned).strip()


def clip(text: str, limit: int) -> str:
    text = strip_html(str(text or ""))
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def is_http_url(value: str) -> bool:
    parsed = urlparse((value or "").strip())
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def flag_emoji(code: str) -> str:
    raw = (code or "").strip().upper()
    if raw == "UK":
        raw = "GB"
    if len(raw) != 2 or not raw.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(ch) - ord("A")) for ch in raw)


def country_label(code: str) -> str:
    raw = (code or "").strip()
    if not raw:
        return "미상"
    name = COUNTRY_KO.get(raw.upper(), raw if len(raw) > 2 else raw.upper())
    iso = raw.upper() if len(raw) == 2 else ""
    return f"{iso} {name}".strip() if iso else name


def translate_industry(value: str) -> str:
    text = strip_html(value or "")
    if not text or text in ("미상", "N/A", "n/a"):
        return "미상"
    key = text.lower().strip()
    if key in INDUSTRY_KO:
        return INDUSTRY_KO[key]
    for eng, ko in INDUSTRY_KO.items():
        if eng in key:
            return ko
    if re.search(r"[가-힣]", text):
        return text
    return text


def today_ymd() -> str:
    return now_utc().astimezone(KST).strftime("%Y-%m-%d")


def format_row_date(value: Any) -> str:
    parsed = parse_datetime(value)
    if parsed:
        return parsed.astimezone(KST).strftime("%Y-%m-%d")
    text = strip_html(str(value or "")).strip()
    match = re.search(r"(\d{4})[-./년 ]\s*(\d{1,2})[-./월 ]\s*(\d{1,2})", text)
    if match:
        return f"{int(match.group(1)):04d}-{int(match.group(2)):02d}-{int(match.group(3)):02d}"
    return today_ymd() if not text or text == "미상" else clip(text, 12)


def iso_from_country_text(value: str) -> str:
    text = strip_html(value or "")
    flag = FLAG_RE.search(text)
    if flag:
        pair = flag.group(0)
        return "".join(chr(ord(ch) - 0x1F1E6 + ord("A")) for ch in pair).lower()
    token = re.search(r"\b([A-Za-z]{2})\b", text)
    if token:
        code = token.group(1).upper()
        if code == "UK":
            return "gb"
        if code in COUNTRY_KO:
            return code.lower()
    for name, code in COUNTRY_ISO_BY_NAME.items():
        if name and name in text:
            return "gb" if code == "uk" else code
    return ""


def country_display_name(value: str, iso: str) -> str:
    text = FLAG_RE.sub("", strip_html(value or "")).strip()
    text = re.sub(r"\b[A-Za-z]{2}\b", "", text).strip(" -/|,")
    if text:
        return text
    return COUNTRY_KO.get(iso.upper(), "미상") if iso else "미상"


def collect_ransomware_victims() -> list[dict[str, Any]]:
    print("[1/5] Ransomware.live 피해자 수집 시작")
    print(f"  - API 호출: {RANSOMWARE_LIVE_URL}")
    cutoff = cutoff_utc()
    headers = {**HTTP_HEADERS, "Accept": "application/json"}

    try:
        resp = requests.get(RANSOMWARE_LIVE_URL, headers=headers, timeout=HTTP_TIMEOUT)
        resp.raise_for_status()
        payload = resp.json()
        print("  - 응답 수신 성공")
    except Exception as exc:
        print(f"[경고] Ransomware.live 수집 실패: {exc}")
        return []

    items = payload if isinstance(payload, list) else payload.get("victims") or payload.get("data") or []
    if not isinstance(items, list):
        print("[경고] Ransomware.live 응답 형식이 리스트가 아닙니다.")
        return []

    victims: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        discovered = parse_datetime(
            item.get("discovered") or item.get("attackdate") or item.get("published")
        )
        if not is_within_24h(discovered, cutoff):
            continue
        country_code = str(item.get("country") or item.get("country_code") or "").strip()
        source_url = str(item.get("url") or "").strip()
        if not is_http_url(source_url):
            source_url = RANSOMWARE_LIVE_HOME
        victims.append(
            {
                "victim": item.get("victim") or item.get("post_title") or "미상",
                "group": item.get("group") or item.get("group_name") or "미상",
                "country_code": country_code or "미상",
                "country": country_label(country_code),
                "industry": translate_industry(str(item.get("activity") or item.get("sector") or "")),
                "domain": item.get("domain") or "",
                "description": clip(str(item.get("description") or ""), 280),
                "discovered": discovered.astimezone(KST).strftime("%Y-%m-%d") if discovered else "",
                "source_url": source_url,
            }
        )

    print(f"Ransomware.live에서 24시간 이내 피해자 {len(victims)}개 수집됨")
    return victims


def parse_feed_entries(
    feed, cutoff: datetime, *, include_missing_dates: bool = False
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for entry in getattr(feed, "entries", []) or []:
        title = strip_html(getattr(entry, "title", "") or "")
        if not title:
            continue
        published = None
        parsed = getattr(entry, "published_parsed", None) or getattr(entry, "updated_parsed", None)
        if parsed:
            try:
                published = datetime(*parsed[:6], tzinfo=timezone.utc)
            except (TypeError, ValueError):
                published = None
        if published is None:
            published = parse_datetime(
                getattr(entry, "published", None)
                or getattr(entry, "updated", None)
                or getattr(entry, "pubDate", None)
            )
        if published is None:
            if not include_missing_dates:
                continue
        elif not is_within_24h(published, cutoff):
            continue
        items.append(
            {
                "title": title,
                "summary": clip(
                    getattr(entry, "summary", "") or getattr(entry, "description", "") or "",
                    400,
                ),
                "url": (getattr(entry, "link", "") or "").strip(),
                "published": published.astimezone(KST).strftime("%Y-%m-%d") if published else today_ymd(),
            }
        )
    return items


def fetch_rss(url: str, timeout: float | None = None) -> Any:
    resp = requests.get(url, headers=HTTP_HEADERS, timeout=timeout or HTTP_TIMEOUT)
    resp.raise_for_status()
    return feedparser.parse(resp.content)


def collect_security_news() -> list[dict[str, Any]]:
    print("[2/5] 보안 뉴스 RSS 수집 시작")
    cutoff = cutoff_utc()
    articles: list[dict[str, Any]] = []

    for source, url in RSS_FEEDS:
        try:
            print(f"  - RSS 수집: {source}")
            feed = fetch_rss(url)
            items = parse_feed_entries(feed, cutoff)
            for item in items:
                articles.append({"source": source, **item})
            print(f"{source}에서 24시간 이내 기사 {len(items)}개 수집됨")
        except Exception as exc:
            print(f"  - [경고] {source} RSS 수집 실패: {exc}")
            print(f"{source}에서 24시간 이내 기사 0개 수집됨")

    print(f"보안 뉴스 RSS 합계 {len(articles)}개 수집됨")
    return articles


def collect_twitter_intel() -> list[dict[str, Any]]:
    print("[3/5] Twitter(X) 위협 인텔리전스 수집 시작 (RSSHub)")
    cutoff = cutoff_utc()
    tweets: list[dict[str, Any]] = []

    for handle in TWITTER_ACCOUNTS:
        collected: list[dict[str, Any]] = []
        last_error = ""
        for template in RSSHUB_TEMPLATES:
            url = template.format(handle=handle)
            try:
                print(f"  - Twitter 수집: @{handle} ({url})")
                feed = fetch_rss(url, timeout=20)
                entries = getattr(feed, "entries", None) or []
                bozo_exc = getattr(feed, "bozo_exception", None)
                if not entries:
                    raise RuntimeError(str(bozo_exc) if bozo_exc else "피드 항목이 비어 있습니다")
                collected = [
                    {"account": handle, **item}
                    for item in parse_feed_entries(feed, cutoff, include_missing_dates=True)
                ]
                last_error = ""
                break
            except Exception as exc:
                last_error = str(exc)
                print(f"    [경고] @{handle} RSSHub 경로 실패, 다음 경로 시도: {exc}")
                continue

        if last_error and not collected:
            print(f"  - [경고] @{handle} 수집 실패(우회 RSS 전부 실패). 다음 계정으로 진행: {last_error}")
        tweets.extend(collected)
        print(f"@{handle}에서 24시간 이내 트윗 {len(collected)}개 수집됨")

    print(f"Twitter 인텔리전스 합계 {len(tweets)}개 수집됨")
    return tweets


def merge_collected_text(
    victims: list[dict[str, Any]],
    articles: list[dict[str, Any]],
    tweets: list[dict[str, Any]],
) -> str:
    print("[4/5] 수집 데이터 병합")
    lines = [
        f"수집 시각: {now_utc().astimezone(KST).strftime('%Y-%m-%d %H:%M KST')}",
        f"조회 범위: 최근 {LOOKBACK_HOURS}시간",
        "",
        "===== [소스 A] Ransomware.live 랜섬웨어 피해자 =====",
        "주의: 사고 유형은 '랜섬웨어', 신뢰도는 '🔴 확인', 산업군은 한국어, 국가는 ISO코드+한국어명, 위협 일자는 YYYY-MM-DD로 기재하세요.",
        "출처_URL은 각 항목의 '출처 URL'을 그대로 사용하세요.",
        "",
    ]
    if victims:
        for i, v in enumerate(victims, start=1):
            lines.append(
                f"{i}. 기업/기관: {v['victim']} | 국가: {v['country']} ({v['country_code']}) | "
                f"산업: {v['industry']} | 공격그룹: {v['group']} | "
                f"도메인: {v['domain'] or '미상'} | 위협 일자: {v['discovered']}"
            )
            lines.append(f"   출처 URL: {v['source_url']}")
            if v["description"]:
                lines.append(f"   설명: {v['description']}")
    else:
        lines.append("(최근 24시간 내 신규 피해자 없음)")

    lines.extend(["", "===== [소스 B] 보안 뉴스 RSS =====", ""])
    if articles:
        for i, a in enumerate(articles, start=1):
            lines.append(f"{i}. [{a['source']}] {a['title']} ({a['published']})")
            if a["summary"]:
                lines.append(f"   요약: {a['summary']}")
            lines.append(f"   기사 원문 링크(URL): {a['url'] or '미상'}")
    else:
        lines.append("(최근 24시간 내 신규 기사 없음)")

    lines.extend(
        [
            "",
            "===== [소스 C] Twitter(X) 위협 인텔리전스 =====",
            "침해사고, 랜섬웨어, 취약점, 악성코드 등 의미 있는 위협만 표에 포함하세요. 단순 잡담·홍보 트윗은 제외하세요.",
            "취약점 공지·CVE·제품 결함이면 기업/기관은 '취약점 공지'로 적으세요. 침해사고인데 회사명을 모르면 '확인필요'로 적으세요.",
            "",
        ]
    )
    if tweets:
        for i, t in enumerate(tweets, start=1):
            lines.append(f"{i}. [@{t['account']}] {t['title']} ({t['published']})")
            if t["summary"]:
                lines.append(f"   요약: {t['summary']}")
            lines.append(f"   트윗 원문 링크(URL): {t['url'] or '미상'}")
    else:
        lines.append("(최근 24시간 내 신규 트윗 없음)")

    merged = "\n".join(lines)
    print(f"[4/5] 병합 완료 (문자 {len(merged):,}자)")
    return merged


def analyze_with_openai(merged_text: str) -> list[dict[str, Any]]:
    print(f"[5/5] OpenAI 분석 시작 (model={OPENAI_MODEL}, json_object)")
    if not OPENAI_API_KEY or OPENAI_API_KEY.startswith("sk-your-"):
        raise RuntimeError("OPENAI_API_KEY가 .env에 없거나 예시 값입니다.")

    client = OpenAI(api_key=OPENAI_API_KEY)
    try:
        response = client.chat.completions.create(
            model=OPENAI_MODEL,
            temperature=0.2,
            response_format={"type": "json_object"},
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        "아래 데이터를 JSON 스키마로만 분석하세요. "
                        "출처_URL은 입력에 있는 URL을 그대로 넣으세요. "
                        "소스 A(Ransomware.live), 소스 B(보안 뉴스 RSS), 소스 C(Twitter)를 융합해 "
                        "의미 있는 침해사고·랜섬웨어 동향·취약점 정보를 표에 포함하세요. "
                        "취약점 공지면 기업/기관은 '취약점 공지', 침해사고인데 회사명을 모르면 '확인필요'로 적으세요. "
                        "단순 잡담 트윗은 제외하세요.\n\n"
                        + merged_text
                    ),
                },
            ],
        )
        raw = (response.choices[0].message.content or "").strip()
        data = json.loads(raw)
        threats = data.get("threats") if isinstance(data, dict) else None
        if not isinstance(threats, list):
            raise RuntimeError("OpenAI JSON에 threats 배열이 없습니다.")
        print(f"[5/5] OpenAI 분석 완료 ({len(threats)}건)")
        return threats
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"OpenAI JSON 파싱 실패: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"OpenAI API 호출 실패: {exc}") from exc


def classify_company_label(name: str, incident_type: str) -> str:
    text = strip_html(name or "").strip()
    incident = strip_html(incident_type or "").lower()
    placeholders = {"", "미상", "해당없음", "없음", "n/a", "na", "unknown", "none"}
    if text.lower() not in placeholders:
        return text
    vuln_hints = ("제로데이", "취약점", "cve", "패치", "rce", "원격 코드", "권한 상승")
    if any(hint in incident for hint in vuln_hints):
        return "취약점 공지"
    return "확인필요"


def normalize_row(item: dict[str, Any]) -> dict[str, str]:
    mapped: dict[str, str] = {}
    for key, value in item.items():
        col = COLUMN_ALIASES.get(str(key).strip(), str(key).strip())
        mapped[col] = clip(value, 200) if value is not None else "미상"
    mapped["출처_URL"] = mapped.get("출처_URL") or RANSOMWARE_LIVE_HOME
    if not is_http_url(mapped["출처_URL"]):
        mapped["출처_URL"] = RANSOMWARE_LIVE_HOME
    mapped["위협 일자"] = format_row_date(mapped.get("위협 일자"))
    mapped["산업군"] = translate_industry(mapped.get("산업군") or "미상")
    mapped["국가_ISO"] = iso_from_country_text(mapped.get("국가") or "")
    mapped["국가명"] = country_display_name(mapped.get("국가") or "", mapped["국가_ISO"])
    result = {col: mapped.get(col) or "미상" for col in COLUMNS}
    result["기업/기관"] = classify_company_label(result.get("기업/기관") or "", result.get("사고 유형") or "")
    result["출처_URL"] = mapped["출처_URL"]
    result["국가_ISO"] = mapped["국가_ISO"]
    result["국가명"] = mapped["국가명"] or "미상"
    return result


def company_cell_html(name: str, source_url: str) -> str:
    safe_name = html.escape(name)
    if not is_http_url(source_url):
        return safe_name
    href = html.escape(source_url, quote=True)
    return (
        f'<a href="{href}" target="_blank" rel="noopener noreferrer">{safe_name}</a>'
    )


def country_cell_html(iso: str, name: str) -> str:
    safe_name = html.escape(name or "미상")
    if iso:
        code = "gb" if iso.lower() == "uk" else iso.lower()
        src = html.escape(f"https://flagcdn.com/w40/{code}.png", quote=True)
        flag = (
            f'<img class="flag" src="{src}" alt="{safe_name}" width="20" height="14" />'
        )
        return f'<span class="country-cell">{flag}{safe_name}</span>'
    return f'<span class="country-cell">{safe_name}</span>'


def build_html_report(threats: list[dict[str, Any]], date_label: str) -> str:
    rows = [normalize_row(item) for item in threats if isinstance(item, dict)]
    header_cells = "".join(
        f'<th onclick="sortTable({idx})" data-col="{idx}">{html.escape(col)}</th>'
        for idx, col in enumerate(COLUMNS)
    )
    body_rows = []
    for row in rows:
        cells = []
        for col in COLUMNS:
            if col == "기업/기관":
                cells.append(f"<td>{company_cell_html(row[col], row['출처_URL'])}</td>")
            elif col == "국가":
                cells.append(f"<td class=\"country\">{country_cell_html(row.get('국가_ISO', ''), row.get('국가명') or row[col])}</td>")
            else:
                cells.append(f"<td>{html.escape(row[col])}</td>")
        body_rows.append(f"<tr>{''.join(cells)}</tr>")
    tbody = "\n".join(body_rows)

    return f"""<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>🚨 {html.escape(date_label)} 국내/해외 사이버 위협 현황</title>
  <link rel="preconnect" href="https://cdn.jsdelivr.net" />
  <link href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard/dist/web/static/pretendard.css" rel="stylesheet" />
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: #f9fafb;
      color: #111827;
      font-family: "Pretendard", -apple-system, "Apple SD Gothic Neo",
        "Noto Sans KR", "Segoe UI", sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 32px 24px 48px;
    }}

    /* ── 페이지 헤더 ── */
    .page-header {{
      max-width: 1480px;
      margin: 0 auto 20px;
      display: flex;
      align-items: baseline;
      gap: 16px;
      flex-wrap: wrap;
    }}
    .page-title {{
      font-size: 22px;
      font-weight: 700;
      color: #111827;
      letter-spacing: -0.3px;
    }}
    .page-meta {{
      font-size: 13px;
      color: #6b7280;
    }}

    /* ── 카드 컨테이너 ── */
    .card {{
      max-width: 1480px;
      margin: 0 auto;
      background: #ffffff;
      border-radius: 12px;
      box-shadow: 0 1px 3px rgba(0, 0, 0, 0.10), 0 1px 2px rgba(0, 0, 0, 0.06);
      overflow: hidden;
    }}

    /* ── 카드 내부 헤더 바 ── */
    .card-header {{
      padding: 16px 24px;
      border-bottom: 1px solid #eaecf0;
      display: flex;
      align-items: center;
      gap: 8px;
    }}
    .badge {{
      display: inline-block;
      background: #fef2f2;
      color: #b91c1c;
      font-size: 11px;
      font-weight: 600;
      padding: 2px 8px;
      border-radius: 99px;
      letter-spacing: 0.3px;
    }}
    .card-title {{
      font-size: 15px;
      font-weight: 600;
      color: #111827;
    }}
    .card-count {{
      margin-left: auto;
      font-size: 13px;
      color: #6b7280;
    }}

    /* ── 표 래퍼 ── */
    .table-wrap {{
      overflow-x: auto;
    }}

    /* ── 표 ── */
    table {{
      width: 100%;
      border-collapse: collapse;
      min-width: 1000px;
    }}

    thead tr {{
      background: #f3f4f6;
    }}

    th {{
      padding: 11px 16px;
      text-align: center;
      font-size: 13px;
      font-weight: 600;
      color: #4b5563;
      letter-spacing: 0.3px;
      white-space: nowrap;
      border-bottom: 1px solid #eaecf0;
      cursor: pointer;
      user-select: none;
      transition: background 0.15s;
    }}
    th:hover {{ background: #e9eaec; }}
    th.sort-asc::after  {{ content: " ▲"; font-size: 10px; opacity: 0.7; }}
    th.sort-desc::after {{ content: " ▼"; font-size: 10px; opacity: 0.7; }}

    td {{
      padding: 14px 16px;
      text-align: center;
      vertical-align: middle;
      font-size: 14px;
      color: #111827;
      border-bottom: 1px solid #eaecf0;
    }}

    tbody tr:last-child td {{ border-bottom: none; }}
    tbody tr:hover td {{ background: #f8fafc; }}

    /* ── 링크 ── */
    a {{
      color: #2563eb;
      text-decoration: none;
      font-weight: 500;
    }}
    a:hover {{ text-decoration: underline; }}

    /* ── 국가 셀 ── */
    .country-cell {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      white-space: nowrap;
    }}
    .flag {{
      width: 20px;
      height: 14px;
      object-fit: cover;
      border-radius: 2px;
      box-shadow: 0 0 0 1px rgba(0, 0, 0, 0.10);
      flex-shrink: 0;
    }}

    /* ── 신뢰도 배지 ── */
    td:last-child {{ white-space: nowrap; }}

    @media (max-width: 768px) {{
      th {{
        font-size: 12px;
        padding: 10px 12px;
      }}
      td {{
        font-size: 12px;
        padding: 10px 12px;
      }}
    }}
  </style>
</head>
<body>
  <div class="page-header">
    <h1 class="page-title">🚨 {html.escape(date_label)} 국내/해외 사이버 위협 현황</h1>
  </div>

  <div class="card">
    <div class="card-header">
      <span class="badge">LIVE</span>
      <span class="card-title">위협 인텔리전스 리포트</span>
      <span class="card-count">최근 24시간 · 총 {len(rows)}건 &nbsp;·&nbsp; 헤더 클릭 시 정렬 · 기업명 클릭 시 원문 이동</span>
    </div>
    <div class="table-wrap" style="overflow-x: auto; -webkit-overflow-scrolling: touch;">
      <table id="threat-table">
        <thead><tr>{header_cells}</tr></thead>
        <tbody>
{tbody}
        </tbody>
      </table>
    </div>
  </div>

  <script>
    let currentCol = -1;
    let currentDir = "asc";

    function cellText(td) {{
      return (td.innerText || td.textContent || "").trim();
    }}

    function sortTable(colIndex) {{
      const table  = document.getElementById("threat-table");
      const tbody  = table.tBodies[0];
      const rows   = Array.from(tbody.rows);
      const dir    = (currentCol === colIndex && currentDir === "asc") ? "desc" : "asc";
      currentCol   = colIndex;
      currentDir   = dir;

      rows.sort((a, b) => {{
        const av = cellText(a.cells[colIndex]);
        const bv = cellText(b.cells[colIndex]);
        return dir === "asc"
          ? av.localeCompare(bv, "ko", {{ numeric: true, sensitivity: "base" }})
          : bv.localeCompare(av, "ko", {{ numeric: true, sensitivity: "base" }});
      }});

      rows.forEach(r => tbody.appendChild(r));
      Array.from(table.tHead.rows[0].cells).forEach((th, i) => {{
        th.classList.remove("sort-asc", "sort-desc");
        if (i === colIndex) th.classList.add(dir === "asc" ? "sort-asc" : "sort-desc");
      }});
    }}
  </script>
</body>
</html>
"""


def save_html_report(html_doc: str, path: Path) -> Path:
    # GitHub Pages 배포용 public 폴더가 없을 수 있으니 생성
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html_doc, encoding="utf-8")
    print(f"[저장] HTML 파일 저장: {path}")
    return path


def slack_client() -> WebClient:
    if not SLACK_BOT_TOKEN.startswith("xoxb-"):
        raise RuntimeError("SLACK_BOT_TOKEN이 없습니다. .env에 xoxb- 토큰을 넣어 주세요.")
    if not SLACK_CHANNEL_ID:
        raise RuntimeError("SLACK_CHANNEL_ID가 없습니다. .env에 채널 ID를 넣어 주세요.")
    return WebClient(token=SLACK_BOT_TOKEN)


def post_empty_notice() -> None:
    slack_client().chat_postMessage(channel=SLACK_CHANNEL_ID, text=EMPTY_MESSAGE)
    print("[전송] Slack 안내 메시지 전송 성공")


def print_env_diagnostics() -> None:
    """민감 정보는 노출하지 않고 환경 변수 설정 여부만 출력."""
    print("[환경] OPENAI_API_KEY:", "설정됨" if OPENAI_API_KEY and not OPENAI_API_KEY.startswith("sk-your-") else "없음/예시값")
    print(
        "[환경] SLACK_BOT_TOKEN:",
        "설정됨 (xoxb-)" if SLACK_BOT_TOKEN.startswith("xoxb-") else "없음 또는 형식 오류",
    )
    print(
        "[환경] SLACK_CHANNEL_ID:",
        f"설정됨 ({SLACK_CHANNEL_ID[:4]}...)" if SLACK_CHANNEL_ID else "없음",
    )


def slack_error_message(exc: Exception) -> str:
    if isinstance(exc, SlackApiError):
        payload = exc.response if hasattr(exc, "response") else {}
        if isinstance(payload, dict):
            return str(payload.get("error") or payload)
        return str(payload)
    return str(exc)


def upload_html_to_slack(path: Path, date_label: str) -> None:
    def infer_dashboard_url() -> str:
        # 1) Actions/로컬에서 명시한 값 우선
        if GITHUB_PAGES_URL:
            return GITHUB_PAGES_URL.rstrip("/") + "/"

        # 2) 로컬 git remote.origin.url에서 owner/repo 추출
        try:
            origin_url = (
                subprocess.check_output(
                    ["git", "config", "--get", "remote.origin.url"],
                    stderr=subprocess.DEVNULL,
                    text=True,
                )
                .strip()
            )
            m = re.search(r"github\.com[:/](?P<owner>[^/]+)/(?P<repo>[^/.]+)", origin_url)
            if m:
                owner = m.group("owner")
                repo = m.group("repo")
                return f"https://{owner}.github.io/{repo}/"
        except Exception:
            pass

        # 3) 추출 불가 시 placeholder
        return "https://YOUR_GITHUB_PAGES_URL_HERE/"

    dashboard_url = infer_dashboard_url()

    comment = (
        f"🚨 *{date_label} 국내/해외 사이버 위협 현황* 🚨\n\n"
        "모바일 및 PC에서 아래 링크를 클릭하여 오늘의 위협 현황 대시보드를 확인하세요.\n"
        f"🔗 *[오늘의 위협 현황 웹으로 보기]({dashboard_url})*"
    )
    print(f"[전송] Slack 대시보드 링크 전송 시작 (channel={SLACK_CHANNEL_ID})")
    try:
        slack_client().chat_postMessage(channel=SLACK_CHANNEL_ID, text=comment)
        print("[전송] Slack 메시지 전송 성공")
    except SlackApiError as exc:
        error = slack_error_message(exc)
        print(f"[오류] Slack API 응답: {error}")
        if error == "not_in_channel":
            raise RuntimeError(
                "봇이 채널에 없습니다. Slack에서 `/invite @봇이름` 으로 초대한 뒤 다시 실행하세요."
            ) from exc
        if error in {"invalid_auth", "token_revoked", "account_inactive"}:
            raise RuntimeError(
                "Slack Bot Token이 잘못되었습니다. GitHub Secrets의 SLACK_BOT_TOKEN을 다시 확인하세요."
            ) from exc
        if error in {"channel_not_found", "is_archived"}:
            raise RuntimeError(
                "Slack 채널 ID가 잘못되었습니다. GitHub Secrets의 SLACK_CHANNEL_ID를 다시 확인하세요."
            ) from exc
        if error == "missing_scope":
            raise RuntimeError(
                "Slack 봇 권한이 부족합니다. Bot Token Scopes에 chat:write를 추가하세요."
            ) from exc
        raise RuntimeError(f"Slack 메시지 전송 실패: {error}") from exc


def send_test_slack() -> None:
    sample = [
        {
            "위협 일자": today_ymd(),
            "기업/기관": "테스트기관",
            "출처_URL": "https://www.ransomware.live/",
            "국가": "KR 한국",
            "산업군": "IT",
            "사고 유형": "정보유출",
            "공격그룹": "미상",
            "공격기법": "피싱 -> 계정탈취",
            "피해 내용": "HTML 링크 테스트",
            "신뢰도": "🟠 조사중",
        }
    ]
    date_label = today_label()
    out_path = html_path(date_label)
    html_doc = build_html_report(sample, date_label)
    save_html_report(html_doc, out_path)
    upload_html_to_slack(out_path, date_label)
    print("테스트 HTML을 Slack 채널로 업로드했습니다.")


def run() -> int:
    date_label = today_label()
    print("=" * 60)
    print("국내외 사이버 위협 현황 봇 시작")
    print(f"오늘 날짜: {date_label}")
    print(f"기준 시각: {now_utc().astimezone(KST).strftime('%Y-%m-%d %H:%M:%S KST')}")
    print_env_diagnostics()
    print("=" * 60)

    try:
        victims = collect_ransomware_victims()
        articles = collect_security_news()
        tweets = collect_twitter_intel()
        if not victims and not articles and not tweets:
            print("[결과] 24시간 내 신규 데이터 없음")
            post_empty_notice()
            return 0

        merged = merge_collected_text(victims, articles, tweets)
        threats = analyze_with_openai(merged)
        if not threats:
            print("[결과] 추출된 위협 없음")
            post_empty_notice()
            return 0

        html_doc = build_html_report(threats, date_label)
        out_path = html_path(date_label)
        save_html_report(html_doc, out_path)
        upload_html_to_slack(out_path, date_label)
        print(f"완료: {out_path.name}을 Slack에 업로드했습니다. ({len(threats)}건)")
        return 0
    except Exception as exc:
        print("[오류] 실행 실패")
        traceback.print_exc()
        try:
            slack_client().chat_postMessage(
                channel=SLACK_CHANNEL_ID,
                text=f"봇 실행 실패: {exc}",
            )
        except Exception as exc2:
            print(f"[오류] Slack 오류 알림 전송도 실패했습니다: {exc2}")
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    if "--test-slack" in sys.argv:
        try:
            send_test_slack()
            sys.exit(0)
        except Exception:
            traceback.print_exc()
            sys.exit(1)
    sys.exit(run())
