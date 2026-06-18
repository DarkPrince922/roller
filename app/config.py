"""Environment-based configuration. Values here are first-run defaults only —
mutable settings (target, strategy, proxy, limits) live in SQLite (see storage.py)
once the bot has started and can be edited live via Telegram."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _split_csv(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def _csv_ints(value: str) -> set[int]:
    return {int(v) for v in _split_csv(value)}


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    telegram_bot_token: str
    telegram_allowed_chat_ids: set[int]

    mws_api_base: str
    mws_api_token: str
    mws_project_id: str
    mws_network_id: str
    mws_region: str
    mws_region_code: str
    mws_zone_code: str
    mws_ip_quota: int

    proxy: str

    hunt_strategy: str
    target_cidrs: list[str]
    target_asns: set[int]
    target_count: int
    max_attempts: int
    max_runtime_min: int
    max_budget: float
    rate_limit_delay_sec: float
    estimated_cost_per_ip_hour: float

    ip2asn_db_path: Path
    db_path: Path
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            telegram_bot_token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            telegram_allowed_chat_ids=_csv_ints(os.environ.get("TELEGRAM_ALLOWED_CHAT_IDS", "")),
            mws_api_base=os.environ.get("MWS_API_BASE", "https://gateway.cloud.mts.ru").rstrip("/"),
            mws_api_token=os.environ.get("MWS_API_TOKEN", ""),
            mws_project_id=os.environ.get("MWS_PROJECT_ID", ""),
            mws_network_id=os.environ.get("MWS_NETWORK_ID", ""),
            mws_region=os.environ.get("MWS_REGION", "msk"),
            mws_region_code=os.environ.get("MWS_REGION_CODE", "msk"),
            mws_zone_code=os.environ.get("MWS_ZONE_CODE", ""),
            mws_ip_quota=int(os.environ.get("MWS_IP_QUOTA", "5")),
            proxy=os.environ.get("PROXY", ""),
            hunt_strategy=os.environ.get("HUNT_STRATEGY", "release_immediately"),
            target_cidrs=_split_csv(os.environ.get("TARGET_CIDRS", "")),
            target_asns=_csv_ints(os.environ.get("TARGET_ASNS", "")),
            target_count=int(os.environ.get("TARGET_COUNT", "1")),
            max_attempts=int(os.environ.get("MAX_ATTEMPTS", "500")),
            max_runtime_min=int(os.environ.get("MAX_RUNTIME_MIN", "120")),
            max_budget=float(os.environ.get("MAX_BUDGET", "0")),
            rate_limit_delay_sec=float(os.environ.get("RATE_LIMIT_DELAY_SEC", "2")),
            estimated_cost_per_ip_hour=float(os.environ.get("ESTIMATED_COST_PER_IP_HOUR", "0")),
            ip2asn_db_path=Path(os.environ.get("IP2ASN_DB_PATH", "/data/ip2asn-v4.tsv")),
            db_path=Path(os.environ.get("DB_PATH", "/data/state.sqlite")),
            log_level=os.environ.get("LOG_LEVEL", "INFO"),
        )


def mask_secret(value: str, keep: int = 2) -> str:
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * (len(value) - keep * 2)}{value[-keep:]}"
