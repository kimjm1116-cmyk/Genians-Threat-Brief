from __future__ import annotations

import logging
from typing import Any

import httpx
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

from src.config import settings
from src.models import ThreatReport

logger = logging.getLogger(__name__)


def _post_webhook(url: str, payload: dict[str, Any]) -> None:
    with httpx.Client(timeout=20) as client:
        resp = client.post(url, json=payload)
        resp.raise_for_status()


def build_slack_blocks(report: ThreatReport) -> list[dict[str, Any]]:
    title = f"🛡️ 국내외 위협현황 | {report.date_label}"
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "국내외 위협현황", "emoji": True},
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*{title}*\n_최근 24시간 침해·공격 사고 요약_"},
        },
        {"type": "divider"},
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"```{report.markdown_table}```",
            },
        },
    ]


def post_report(report: ThreatReport) -> None:
    fallback = f"국내외 위협현황 | {report.date_label}\n{report.markdown_table[:500]}"
    blocks = build_slack_blocks(report)

    if settings.slack_webhook_url:
        _post_webhook(settings.slack_webhook_url, {"text": fallback, "blocks": blocks})
        logger.info("Slack 전송 완료 (%s행)", len(report.rows))
        return

    if settings.slack_bot_token and settings.slack_channel_id:
        client = WebClient(token=settings.slack_bot_token)
        client.chat_postMessage(channel=settings.slack_channel_id, text=fallback, blocks=blocks)
        logger.info("Slack Bot 전송 완료 (%s행)", len(report.rows))
        return

    raise RuntimeError("Slack 전송 설정이 없습니다. SLACK_WEBHOOK_URL 또는 BOT TOKEN+CHANNEL을 확인하세요.")


def post_error(message: str) -> None:
    text = f":rotating_light: 위협현황 봇 실행 실패\n```{message[:2500]}```"
    payload = {
        "text": text,
        "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": text}}],
    }
    url = settings.slack_alert_webhook_url or settings.slack_webhook_url
    try:
        if url:
            _post_webhook(url, payload)
            return
        if settings.slack_bot_token and settings.slack_channel_id:
            WebClient(token=settings.slack_bot_token).chat_postMessage(
                channel=settings.slack_channel_id,
                text=text,
                blocks=payload["blocks"],
            )
    except (httpx.HTTPError, SlackApiError):
        logger.exception("에러 알림 전송도 실패했습니다.")


def send_webhook_test() -> None:
    sample = (
        "| 기업/기관 | 산업군 | 사고 유형 | 공격그룹 | 공격기법 | 피해 내용 | 신뢰도 |\n"
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n"
        "| 테스트기관 | IT | 정보유출 | 미상 | 피싱 -> 계정탈취 | 테스트 메시지 | 🟠 조사중 |"
    )
    report = ThreatReport(date_label="테스트", markdown_table=sample, rows=[])
    post_report(report)
