from __future__ import annotations

import json
import logging
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from openai import OpenAI
from tenacity import retry, stop_after_attempt, wait_exponential

from src.config import settings
from src.links import is_valid_article_url
from src.models import Article, ThreatReport, ThreatRow

logger = logging.getLogger(__name__)

TABLE_HEADER = (
    "| 기업/기관 | 산업군 | 사고 유형 | 공격그룹 | 공격기법 | 피해 내용 | 신뢰도 |\n"
    "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
)

SYSTEM_PROMPT = """당신은 글로벌 최고 수준의 CTI(Cyber Threat Intelligence) 분석가이자 보안 뉴스 큐레이터입니다.
입력된 보안 관련 텍스트 데이터를 분석하여 위협 현황 리포트 행(row)을 작성합니다.

반드시 JSON만 출력합니다.
영문 기사는 한국어로 번역하여 기재합니다.
같은 사건·같은 기업·같은 원문은 한 행만 포함합니다.
실제 침해·공격·유출·랜섬웨어·DDoS·계정탈취 등 사고성 기사만 선별합니다.
일반적인 제품 출시, M&A, 규제 동향만 다룬 기사는 제외합니다.

컬럼 가이드:
1. organization: 피해 타겟 이름. 특정 어려우면 A기업, B기관 등 익명화
2. industry: 제조, 금융, 교육, 의료, IT, 공공 등
3. incident_type: 랜섬웨어, 정보유출, 계정탈취, DDoS, 디페이스 등
4. attack_group: LockBit, Lazarus 등. 미상이면 "미상"
5. attack_technique: Kill Chain을 " -> "로 연결 (예: 피싱 -> 계정탈취 -> DB 접근)
6. damage: 핵심 피해만 간결히
7. confidence: 반드시 아래 3가지 중 하나
   - "🔴 확인"
   - "🟠 조사중"
   - "🟡 공격자 주장"

각 행에 source_id(후보 기사 id 정수)를 포함하세요."""


def _articles_payload(articles: list[Article]) -> list[dict]:
    return [
        {
            "id": idx,
            "title": a.title,
            "url": a.url,
            "source": a.source,
            "region": a.region,
            "snippet": a.summary_raw[:400],
        }
        for idx, a in enumerate(articles)
    ]


def _user_prompt(articles: list[Article], date_label: str) -> str:
    return f"""날짜: {date_label}
최대 {settings.max_report_rows}개 행을 선별하세요. 국내·해외를 균형 있게 포함하되, 중요도가 높은 사고를 우선합니다.

JSON 형식:
{{
  "rows": [
    {{
      "source_id": 0,
      "organization": "",
      "industry": "",
      "incident_type": "",
      "attack_group": "",
      "attack_technique": "",
      "damage": "",
      "confidence": "🔴 확인"
    }}
  ]
}}

후보 기사:
{json.dumps(_articles_payload(articles), ensure_ascii=False)}
"""


def _clean_cell(text: str, max_len: int = 80) -> str:
    cleaned = re.sub(r"\s+", " ", (text or "").strip())
    cleaned = cleaned.replace("|", "/")
    return cleaned[:max_len].rstrip(" ,;.")


def _normalize_confidence(raw: str) -> str:
    text = (raw or "").strip()
    if "🔴" in text or "확인" in text:
        return "🔴 확인"
    if "🟡" in text or "공격자" in text or "주장" in text:
        return "🟡 공격자 주장"
    return "🟠 조사중"


def build_markdown_table(rows: list[ThreatRow]) -> str:
    lines = [TABLE_HEADER]
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    _clean_cell(row.organization, 40),
                    _clean_cell(row.industry, 16),
                    _clean_cell(row.incident_type, 20),
                    _clean_cell(row.attack_group, 24),
                    _clean_cell(row.attack_technique, 60),
                    _clean_cell(row.damage, 60),
                    _clean_cell(row.confidence, 16),
                ]
            )
            + " |"
        )
    return "\n".join(lines)


@retry(wait=wait_exponential(min=2, max=20), stop=stop_after_attempt(3), reraise=True)
def _call_llm(client: OpenAI, articles: list[Article], date_label: str) -> dict:
    response = client.chat.completions.create(
        model=settings.openai_model,
        temperature=0.2,
        response_format={"type": "json_object"},
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": _user_prompt(articles, date_label)},
        ],
    )
    content = response.choices[0].message.content or "{}"
    return json.loads(content)


def _map_rows(raw_rows: list[dict], articles: list[Article]) -> list[ThreatRow]:
    mapped: list[ThreatRow] = []
    seen_orgs: set[str] = set()

    for item in raw_rows or []:
        try:
            idx = int(item.get("source_id", item.get("id", -1)))
            article = articles[idx]
        except (ValueError, IndexError, TypeError):
            continue
        if not is_valid_article_url(article.url):
            continue

        org = _clean_cell(item.get("organization") or article.title, 40)
        org_key = re.sub(r"[^0-9a-z가-힣]+", "", org.lower())
        if org_key and org_key in seen_orgs:
            continue
        if org_key:
            seen_orgs.add(org_key)

        mapped.append(
            ThreatRow(
                organization=org,
                industry=_clean_cell(item.get("industry") or "미상", 16),
                incident_type=_clean_cell(item.get("incident_type") or "침해사고", 20),
                attack_group=_clean_cell(item.get("attack_group") or "미상", 24),
                attack_technique=_clean_cell(item.get("attack_technique") or "미상", 60),
                damage=_clean_cell(item.get("damage") or article.summary_raw[:60], 60),
                confidence=_normalize_confidence(item.get("confidence") or ""),
                source_url=article.url,
            )
        )
        if len(mapped) >= settings.max_report_rows:
            break
    return mapped


def analyze(articles: list[Article]) -> ThreatReport:
    if not settings.openai_api_key:
        raise RuntimeError("OPENAI_API_KEY가 비어 있습니다. .env를 확인하세요.")
    if not articles:
        raise ValueError("분석할 기사가 없습니다.")

    now = datetime.now(ZoneInfo(settings.tz))
    date_label = now.strftime("%Y-%m-%d (%a)")
    client = OpenAI(api_key=settings.openai_api_key)
    raw = _call_llm(client, articles, date_label)
    rows = _map_rows(raw.get("rows") or [], articles)

    if not rows:
        raise RuntimeError("LLM이 유효한 위협 현황 행을 생성하지 못했습니다.")

    return ThreatReport(
        date_label=date_label,
        rows=rows,
        markdown_table=build_markdown_table(rows),
    )
