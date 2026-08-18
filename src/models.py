from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class Article(BaseModel):
    title: str
    url: str
    source: str
    published_at: Optional[datetime] = None
    summary_raw: str = ""
    language: str = "en"
    region: str = "global"


class ThreatRow(BaseModel):
    organization: str
    industry: str
    incident_type: str
    attack_group: str
    attack_technique: str
    damage: str
    confidence: str
    source_url: str = ""


class ThreatReport(BaseModel):
    date_label: str
    rows: list[ThreatRow] = Field(default_factory=list)
    markdown_table: str = ""
