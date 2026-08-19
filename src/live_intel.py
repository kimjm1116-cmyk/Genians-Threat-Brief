"""Check Point ThreatMap / DuckIntel Dashboard 공개 API 수집기.

브라우저 렌더링 없이 JSON·CSV·짧은 SSE 샘플만 사용한다.
실패해도 예외를 삼키고 빈 목록을 반환해 전체 파이프라인을 멈추지 않는다.
"""

from __future__ import annotations

import csv
import io
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import quote

import requests

KST = timezone(timedelta(hours=9))
LOOKBACK_HOURS = 24
HTTP_TIMEOUT = 25
SSE_SECONDS = 8
SSE_MAX_EVENTS = 50
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
)
HTTP_HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "application/json,text/plain,*/*",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
}

CHECKPOINT_HOME = "https://threatmap.checkpoint.com/"
CHECKPOINT_TOPSTATS = "https://threatmap-api.checkpoint.com/ThreatMap/api/topStats"
CHECKPOINT_FEED = "https://threatmap-api.checkpoint.com/ThreatMap/api/feed"
CHECKPOINT_HEADERS = {
    **HTTP_HEADERS,
    "Origin": "https://threatmap.checkpoint.com",
    "Referer": CHECKPOINT_HOME,
}

DUCKINTEL_HOME = "https://www.duckintel.io/dashboard/"
DUCKINTEL_PROXY = "https://api.duckintel.io/"
URLHAUS_CSV_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"
THREATFOX_CSV_RECENT = "https://threatfox.abuse.ch/export/csv/recent/"
FEODO_JSON = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
CISA_KEV_JSON = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

URLHAUS_GENERIC_TAGS = {
    "",
    "none",
    "32-bit",
    "64-bit",
    "elf",
    "exe",
    "dll",
    "mips",
    "arm",
    "sh",
    "opendir",
    "ua-wget",
    "ascii",
    "doc",
    "pdf",
    "html",
}

COUNTRY_KO = {
    "US": "미국",
    "KR": "한국",
    "JP": "일본",
    "CN": "중국",
    "GB": "영국",
    "UK": "영국",
    "DE": "독일",
    "FR": "프랑스",
    "IT": "이탈리아",
    "ES": "스페인",
    "NL": "네덜란드",
    "BE": "벨기에",
    "CH": "스위스",
    "AT": "오스트리아",
    "SE": "스웨덴",
    "NO": "노르웨이",
    "DK": "덴마크",
    "FI": "핀란드",
    "PL": "폴란드",
    "CZ": "체코",
    "AU": "호주",
    "NZ": "뉴질랜드",
    "CA": "캐나다",
    "MX": "멕시코",
    "BR": "브라질",
    "AR": "아르헨티나",
    "CL": "칠레",
    "IN": "인도",
    "SG": "싱가포르",
    "MY": "말레이시아",
    "TH": "태국",
    "VN": "베트남",
    "PH": "필리핀",
    "ID": "인도네시아",
    "TW": "대만",
    "HK": "홍콩",
    "AE": "아랍에미리트",
    "SA": "사우디아라비아",
    "IL": "이스라엘",
    "TR": "튀르키예",
    "ZA": "남아프리카공화국",
    "EG": "이집트",
    "RU": "러시아",
    "UA": "우크라이나",
    "IE": "아일랜드",
    "PT": "포르투갈",
    "GR": "그리스",
    "RO": "루마니아",
    "HU": "헝가리",
    "ET": "에티오피아",
    "UZ": "우즈베키스탄",
    "NP": "네팔",
    "AO": "앙골라",
    "AL": "알바니아",
    "MA": "모로코",
}


def _now_utc() -> datetime:
    return datetime.now(timezone.utc)


def _cutoff_utc() -> datetime:
    return _now_utc() - timedelta(hours=LOOKBACK_HOURS)


def _today_ymd() -> str:
    return _now_utc().astimezone(KST).strftime("%Y-%m-%d")


def _parse_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        dt = value
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    text = str(value).strip().strip('"').replace(" UTC", "")
    if not text:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(text[:19] if "T" not in text and len(text) >= 19 else text[:19], fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _is_within_24h(dt: datetime | None, cutoff: datetime) -> bool:
    if dt is None:
        return False
    return cutoff <= dt <= _now_utc() + timedelta(minutes=10)


def _country_label(code: str) -> str:
    raw = (code or "").strip().upper()
    if not raw or raw in {"NONE", "NULL", "N/A", "ZZ", "XX"}:
        return "미상"
    if raw == "UK":
        raw = "GB"
    name = COUNTRY_KO.get(raw, raw)
    return f"{raw} {name}" if len(raw) == 2 and raw.isalpha() else name


def _clean(value: Any) -> str:
    return str(value or "").strip().strip('"').strip()


def _record(
    *,
    date: str,
    target: str,
    country_code: str,
    attack_type: str,
    source_url: str,
    technique: str = "",
    summary: str = "",
    industry: str = "미상",
    group: str = "미상",
    count: int = 1,
) -> dict[str, Any]:
    url = (source_url or "").strip()
    if not url.startswith("http"):
        url = CHECKPOINT_HOME if "checkpoint" in (source_url or "").lower() else DUCKINTEL_HOME
    return {
        "date": date or _today_ymd(),
        "target": target or "확인필요",
        "country_code": (country_code or "").strip().upper(),
        "country": _country_label(country_code),
        "attack_type": attack_type or "미상",
        "technique": technique or "미상",
        "source_url": url,
        "summary": summary or "",
        "industry": industry or "미상",
        "group": group or "미상",
        "count": count,
    }


def _http_get(url: str, *, headers: dict[str, str] | None = None, timeout: float = HTTP_TIMEOUT, stream: bool = False):
    return requests.get(
        url,
        headers=headers or HTTP_HEADERS,
        timeout=timeout,
        stream=stream,
    )


def _fetch_duckintel_feed(url: str, timeout: float = 40) -> str:
    """DuckIntel CORS 프록시(`?feed=`)를 쓰고, 실패하면 원본 피드를 직접 호출한다."""
    headers = {
        **HTTP_HEADERS,
        "Referer": DUCKINTEL_HOME,
        "Origin": "https://www.duckintel.io",
    }
    proxy_url = f"{DUCKINTEL_PROXY}?feed={quote(url, safe=':/')}"
    try:
        resp = _http_get(proxy_url, headers=headers, timeout=timeout)
        if resp.status_code in {401, 403, 502, 503} or not resp.ok:
            raise RuntimeError(f"proxy HTTP {resp.status_code}")
        text = resp.text or ""
        if text.strip().startswith("{") and '"error"' in text[:200]:
            raise RuntimeError(text[:180])
        return text
    except Exception as exc:
        print(f"    [경고] DuckIntel 프록시 실패, 원본 피드 직접 호출: {exc}")
        resp = _http_get(url, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.text


def _parse_commented_csv(text: str) -> list[list[str]]:
    data_lines: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        data_lines.append(line)
    if not data_lines:
        return []
    reader = csv.reader(io.StringIO("\n".join(data_lines)), skipinitialspace=True)
    rows: list[list[str]] = []
    for row in reader:
        cleaned = [_clean(col) for col in row]
        if any(cleaned):
            rows.append(cleaned)
    return rows


def _malware_family_from_tags(tags: str) -> str:
    names: list[str] = []
    for tag in (tags or "").split(","):
        name = tag.strip()
        if not name or name.lower() in URLHAUS_GENERIC_TAGS:
            continue
        if re.fullmatch(r"[\d._-]+", name):
            continue
        if re.fullmatch(r"\d{1,3}(?:-\d{1,3}){3}", name):
            continue
        names.append(name)
    return names[0] if names else "미상"


def collect_checkpoint_threatmap() -> list[dict[str, Any]]:
    """Check Point ThreatMap `topStats` JSON + 짧은 SSE `feed` 샘플."""
    print("[4/7] Check Point ThreatMap 수집 시작")
    print(f"  - JSON: {CHECKPOINT_TOPSTATS}")
    print(f"  - SSE 샘플: {CHECKPOINT_FEED} ({SSE_SECONDS}초, 최대 {SSE_MAX_EVENTS}건)")
    try:
        return _collect_checkpoint_threatmap()
    except Exception as exc:
        print(f"[경고] Check Point ThreatMap 수집 실패, 건너뜀: {exc}")
        print("Check Point ThreatMap에서 24시간 동향 0개 수집됨")
        return []


def _collect_checkpoint_threatmap() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    today = _today_ymd()

    try:
        resp = _http_get(
            CHECKPOINT_TOPSTATS,
            headers={**CHECKPOINT_HEADERS, "Accept": "application/json"},
            timeout=HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        stats = resp.json() if resp.content else {}
        if not isinstance(stats, dict):
            stats = {}

        for country in (stats.get("countries") or [])[:5]:
            if not isinstance(country, dict):
                continue
            code = _clean(country.get("id"))
            fraction = country.get("fraction")
            pct = f"{float(fraction) * 100:.0f}%" if isinstance(fraction, (int, float)) else "미상"
            items.append(
                _record(
                    date=today,
                    target="확인필요",
                    country_code=code,
                    attack_type="사이버 공격 집중",
                    technique="국가별 상대 공격량(Check Point topStats)",
                    source_url=CHECKPOINT_HOME,
                    summary=f"최근 구간 상대 공격 비중 {pct} (대상 국가 {code})",
                    count=1,
                )
            )

        malware_types = [
            _clean(item.get("id"))
            for item in (stats.get("malwareTypes") or [])
            if isinstance(item, dict) and _clean(item.get("id"))
        ]
        industries = [
            _clean(item.get("id"))
            for item in (stats.get("industries") or [])
            if isinstance(item, dict) and _clean(item.get("id"))
        ]
        if malware_types or industries:
            items.append(
                _record(
                    date=today,
                    target="확인필요",
                    country_code="",
                    attack_type="악성코드" if malware_types else "사이버 공격",
                    technique=", ".join(malware_types[:5]) or "미상",
                    source_url=CHECKPOINT_HOME,
                    industry=industries[0] if industries else "미상",
                    summary=(
                        f"주요 악성코드 유형: {', '.join(malware_types[:5]) or '미상'} / "
                        f"주요 산업: {', '.join(industries[:5]) or '미상'}"
                    ),
                )
            )
        print(f"  - topStats 파싱 {len(items)}건")
    except Exception as exc:
        print(f"  - [경고] Check Point topStats 수집 실패: {exc}")

    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    today_count = 0
    period_24h = 0
    sampled = 0
    try:
        with _http_get(
            CHECKPOINT_FEED,
            headers={**CHECKPOINT_HEADERS, "Accept": "text/event-stream"},
            timeout=(10, SSE_SECONDS + 2),
            stream=True,
        ) as resp:
            resp.raise_for_status()
            deadline = time.monotonic() + SSE_SECONDS
            for raw_line in resp.iter_lines(decode_unicode=True):
                if time.monotonic() > deadline or sampled >= SSE_MAX_EVENTS:
                    break
                if not raw_line:
                    continue
                line = raw_line.strip()
                if not line.startswith("data:"):
                    continue
                payload_text = line[5:].strip()
                if not payload_text:
                    continue
                try:
                    payload = json.loads(payload_text)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue

                if "recentPeriod" in payload or "today" in payload:
                    today_count = int(payload.get("today") or 0)
                    period = payload.get("recentPeriod") or []
                    if isinstance(period, list):
                        nums = [int(x) for x in period[-24:] if isinstance(x, (int, float))]
                        period_24h = sum(nums)
                    continue

                name = _clean(payload.get("a_n"))
                if not name:
                    continue
                sampled += 1
                atype = _clean(payload.get("a_t")) or "exploit"
                dest = _clean(payload.get("d_co"))
                src = _clean(payload.get("s_co"))
                key = (name, atype, dest)
                bucket = grouped.setdefault(
                    key,
                    {
                        "name": name,
                        "attack_type": atype,
                        "dest": dest,
                        "src": src,
                        "count": 0,
                    },
                )
                bucket["count"] += int(payload.get("a_c") or 1)
    except Exception as exc:
        print(f"  - [경고] Check Point SSE feed 수집 실패: {exc}")

    ranked = sorted(grouped.values(), key=lambda item: item["count"], reverse=True)[:12]
    for item in ranked:
        dest = item["dest"]
        src = item["src"]
        items.append(
            _record(
                date=today,
                target="확인필요",
                country_code=dest,
                attack_type=item["attack_type"],
                technique=item["name"],
                source_url=CHECKPOINT_HOME,
                summary=(
                    f"실시간 관측 {item['count']}건 / 출발 {src or '미상'} → 대상 {dest or '미상'}"
                ),
                count=item["count"],
            )
        )

    if today_count or period_24h:
        items.append(
            _record(
                date=today,
                target="확인필요",
                country_code="",
                attack_type="글로벌 공격 동향",
                technique="Check Point ThreatMap counter",
                source_url=CHECKPOINT_HOME,
                summary=(
                    f"오늘 누적 공격 {today_count:,}건, 최근 24시간 구간 합계 {period_24h:,}건"
                ),
                count=today_count or period_24h,
            )
        )

    print(f"Check Point ThreatMap에서 24시간 동향 {len(items)}개 수집됨 (SSE 샘플 {sampled}건)")
    return items


def _collect_urlhaus(cutoff: datetime) -> list[dict[str, Any]]:
    text = _fetch_duckintel_feed(URLHAUS_CSV_RECENT)
    rows = _parse_commented_csv(text)
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if len(row) < 8:
            continue
        discovered = _parse_datetime(row[1])
        if not _is_within_24h(discovered, cutoff):
            continue
        threat = row[5] if len(row) > 5 else "malware_download"
        tags = row[6] if len(row) > 6 else ""
        family = _malware_family_from_tags(tags)
        link = row[7] if len(row) > 7 else "https://urlhaus.abuse.ch/"
        key = family if family != "미상" else threat
        bucket = grouped.setdefault(
            key,
            {
                "family": family,
                "threat": threat,
                "count": 0,
                "link": link,
                "date": discovered.astimezone(KST).strftime("%Y-%m-%d") if discovered else _today_ymd(),
            },
        )
        bucket["count"] += 1
        bucket["link"] = link or bucket["link"]

    ranked = sorted(grouped.values(), key=lambda item: item["count"], reverse=True)[:8]
    items: list[dict[str, Any]] = []
    for item in ranked:
        attack_type = "악성코드 유포" if "malware" in (item["threat"] or "").lower() else item["threat"]
        items.append(
            _record(
                date=item["date"],
                target=item["family"] if item["family"] != "미상" else "확인필요",
                country_code="",
                attack_type=attack_type,
                technique=item["threat"],
                source_url=item["link"] or "https://urlhaus.abuse.ch/",
                group=item["family"],
                summary=f"URLhaus 최근 24시간 {item['count']}건 관측 (태그 {item['family']})",
                count=item["count"],
            )
        )
    print(f"    URLhaus 24시간 패밀리 {len(items)}개")
    return items


def _collect_threatfox(cutoff: datetime) -> list[dict[str, Any]]:
    text = _fetch_duckintel_feed(THREATFOX_CSV_RECENT)
    rows = _parse_commented_csv(text)
    grouped: dict[str, dict[str, Any]] = {}
    for row in rows:
        if len(row) < 8:
            continue
        discovered = _parse_datetime(row[0])
        if not _is_within_24h(discovered, cutoff):
            continue
        threat_type = row[4] if len(row) > 4 else ""
        malware_id = row[5] if len(row) > 5 else ""
        family = row[7] if len(row) > 7 else malware_id
        if family.lower().startswith("unknown") or family in {"", "None", "미상"}:
            continue
        reference = ""
        if len(row) > 9 and row[9].startswith("http"):
            reference = row[9]
        key = family
        bucket = grouped.setdefault(
            key,
            {
                "family": family,
                "threat_type": threat_type,
                "malware_id": malware_id,
                "count": 0,
                "link": reference,
                "date": discovered.astimezone(KST).strftime("%Y-%m-%d") if discovered else _today_ymd(),
            },
        )
        bucket["count"] += 1
        if reference:
            bucket["link"] = reference

    ranked = sorted(grouped.values(), key=lambda item: item["count"], reverse=True)[:8]
    type_map = {
        "payload_delivery": "악성코드 유포",
        "botnet_cc": "봇넷 C2",
        "payload": "악성코드 페이로드",
    }
    items: list[dict[str, Any]] = []
    for item in ranked:
        source = item["link"] or f"https://threatfox.abuse.ch/browse.php?search=malware:{quote(item['malware_id'] or item['family'])}"
        items.append(
            _record(
                date=item["date"],
                target=item["family"],
                country_code="",
                attack_type=type_map.get(item["threat_type"], item["threat_type"] or "악성코드"),
                technique=item["malware_id"] or item["family"],
                source_url=source,
                group=item["family"],
                summary=f"ThreatFox 최근 24시간 IOC {item['count']}건 ({item['threat_type'] or '미상'})",
                count=item["count"],
            )
        )
    print(f"    ThreatFox 24시간 패밀리 {len(items)}개")
    return items


def _collect_feodo(cutoff: datetime) -> list[dict[str, Any]]:
    text = _fetch_duckintel_feed(FEODO_JSON, timeout=HTTP_TIMEOUT)
    payload = json.loads(text)
    if not isinstance(payload, list):
        return []
    grouped: dict[str, dict[str, Any]] = {}
    for item in payload:
        if not isinstance(item, dict):
            continue
        discovered = _parse_datetime(item.get("last_online") or item.get("first_seen"))
        if not _is_within_24h(discovered, cutoff):
            continue
        country = _clean(item.get("country"))
        malware = _clean(item.get("malware")) or "Feodo"
        key = f"{malware}|{country}"
        bucket = grouped.setdefault(
            key,
            {
                "malware": malware,
                "country": country,
                "count": 0,
                "date": discovered.astimezone(KST).strftime("%Y-%m-%d") if discovered else _today_ymd(),
            },
        )
        bucket["count"] += 1
    items = [
        _record(
            date=item["date"],
            target=item["malware"],
            country_code=item["country"],
            attack_type="봇넷 C2",
            technique="Feodo Tracker",
            source_url="https://feodotracker.abuse.ch/",
            group=item["malware"],
            summary=f"Feodo Tracker 최근 24시간 C2 {item['count']}건",
            count=item["count"],
        )
        for item in sorted(grouped.values(), key=lambda row: row["count"], reverse=True)[:8]
    ]
    print(f"    Feodo Tracker 24시간 C2 {len(items)}개")
    return items


def _collect_cisa_kev(cutoff: datetime) -> list[dict[str, Any]]:
    text = _fetch_duckintel_feed(CISA_KEV_JSON, timeout=40)
    payload = json.loads(text)
    vulns = payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(vulns, list):
        return []
    # dateAdded는 날짜만 있으므로 어제(UTC) 이후를 24시간 범위로 본다.
    floor = (cutoff.date() - timedelta(days=0)).isoformat()
    items: list[dict[str, Any]] = []
    for vuln in vulns:
        if not isinstance(vuln, dict):
            continue
        added = _clean(vuln.get("dateAdded"))
        if not added or added < floor:
            continue
        cve = _clean(vuln.get("cveID"))
        vendor = _clean(vuln.get("vendorProject"))
        name = _clean(vuln.get("vulnerabilityName"))
        product = _clean(vuln.get("product"))
        source = f"https://nvd.nist.gov/vuln/detail/{cve}" if cve else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
        items.append(
            _record(
                date=added,
                target="취약점 공지",
                country_code="US",
                attack_type="제로데이" if "zero" in (name + " " + _clean(vuln.get("shortDescription"))).lower() else "취약점",
                technique=cve or name,
                source_url=source,
                industry="IT",
                summary=f"{vendor} {product} / {name} (CISA KEV {added})",
                group="미상",
            )
        )
        if len(items) >= 12:
            break
    print(f"    CISA KEV 최근 등록 {len(items)}개")
    return items


def collect_duckintel() -> list[dict[str, Any]]:
    """DuckIntel Dashboard가 쓰는 abuse.ch / CISA 공개 피드를 수집한다."""
    print("[5/7] DuckIntel Dashboard 수집 시작")
    print(f"  - CORS 프록시: {DUCKINTEL_PROXY}?feed=<url>")
    try:
        return _collect_duckintel()
    except Exception as extra:
        print(f"[경고] DuckIntel Dashboard 수집 실패, 건너뜀: {extra}")
        print("DuckIntel Dashboard에서 24시간 이내 위협 0개 수집됨")
        return []


def _collect_duckintel() -> list[dict[str, Any]]:
    cutoff = _cutoff_utc()
    items: list[dict[str, Any]] = []

    collectors = (
        ("URLhaus", _collect_urlhaus),
        ("ThreatFox", _collect_threatfox),
        ("Feodo Tracker", _collect_feodo),
        ("CISA KEV", _collect_cisa_kev),
    )
    for name, fn in collectors:
        try:
            print(f"  - {name} 피드 수집")
            items.extend(fn(cutoff))
        except Exception as exc:
            print(f"  - [경고] DuckIntel/{name} 수집 실패: {exc}")

    print(f"DuckIntel Dashboard에서 24시간 이내 위협 {len(items)}개 수집됨")
    return items
