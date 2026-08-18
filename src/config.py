from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv
from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT_DIR = Path(__file__).resolve().parents[1]
load_dotenv(ROOT_DIR / ".env")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(ROOT_DIR / ".env"), extra="ignore")

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"

    slack_webhook_url: str = ""
    slack_bot_token: str = ""
    slack_channel_id: str = ""
    slack_alert_webhook_url: str = ""

    newsapi_key: str = ""

    lookback_hours: int = 24
    max_collected_articles: int = 100
    max_report_rows: int = 12
    tz: str = "Asia/Seoul"

    http_timeout: float = 20.0
    user_agent: str = "ThreatIntelDailyBot/1.0 (+internal CTI briefing)"


settings = Settings()
