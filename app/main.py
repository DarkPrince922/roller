"""Entry point: load config, wire up storage/proxy/MWS client/hunter, start
the Telegram bot. Run with `python -m app.main` (or via the Dockerfile).

Async setup happens in `post_init`/`post_shutdown` rather than around
`run_polling()` itself -- `Application.run_polling()` manages its own event
loop internally, so it can't be awaited from inside one we created ourselves.
"""
from __future__ import annotations

import logging
import logging.handlers

from telegram.ext import Application, ApplicationBuilder

from app.asn_resolver import AsnResolver
from app.bot.handlers import register_handlers
from app.bot.notifications import make_notifier
from app.config import Settings
from app.context import AppContext
from app.hunter import HuntLimits, Hunter
from app.matcher import TargetConfig
from app.mws_client import MwsClient
from app.proxy import ProxyConfig, build_connector
from app.storage import Storage

logger = logging.getLogger(__name__)


def setup_logging(settings: Settings) -> None:
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    file_handler = logging.handlers.RotatingFileHandler(
        settings.db_path.parent / "app.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8",
    )
    file_handler.setFormatter(fmt)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logging.basicConfig(level=settings.log_level, handlers=[file_handler, stream_handler])


async def seed_config_defaults(storage: Storage, settings: Settings) -> None:
    await storage.seed_config_default("proxy", settings.proxy)
    await storage.seed_config_default("strategy", settings.hunt_strategy)
    await storage.seed_config_default("target_count", str(settings.target_count))
    await storage.seed_config_default("max_attempts", str(settings.max_attempts))
    await storage.seed_config_default("max_runtime_min", str(settings.max_runtime_min))
    await storage.seed_config_default("max_budget", str(settings.max_budget))
    if await storage.get_config("target") is None:
        target = TargetConfig(cidrs=settings.target_cidrs, asns=settings.target_asns)
        await storage.set_config_json("target", target.to_dict())


async def load_hunt_limits(storage: Storage, settings: Settings) -> HuntLimits:
    target_dict = await storage.get_config_json("target", {})
    return HuntLimits(
        strategy=await storage.get_config("strategy", settings.hunt_strategy),
        target=TargetConfig.from_dict(target_dict),
        target_count=int(await storage.get_config("target_count", str(settings.target_count))),
        max_attempts=int(await storage.get_config("max_attempts", str(settings.max_attempts))),
        max_runtime_min=int(await storage.get_config("max_runtime_min", str(settings.max_runtime_min))),
        max_budget=float(await storage.get_config("max_budget", str(settings.max_budget))),
        rate_limit_delay_sec=settings.rate_limit_delay_sec,
        estimated_cost_per_ip_hour=settings.estimated_cost_per_ip_hour,
        quota=settings.mws_ip_quota,
    )


async def post_init(application: Application) -> None:
    settings: Settings = application.bot_data["settings"]

    storage = Storage(str(settings.db_path))
    await storage.connect()
    await seed_config_defaults(storage, settings)

    proxy_raw = await storage.get_config("proxy", settings.proxy) or ""
    proxy_cfg = ProxyConfig.parse(proxy_raw) if proxy_raw else None
    connector = build_connector(proxy_cfg)

    resolver = AsnResolver(settings.ip2asn_db_path)
    resolver.load()

    mws = MwsClient(settings, connector)
    await mws.__aenter__()

    limits = await load_hunt_limits(storage, settings)
    notifier = make_notifier(application, settings.telegram_allowed_chat_ids)
    hunter = Hunter(storage, mws, resolver, limits, notifier)

    ctx = AppContext(settings, storage, resolver, mws, hunter, proxy_raw)
    application.bot_data["ctx"] = ctx

    await hunter.sync_from_api()
    logger.info("startup complete, %d IP(s) currently reserved", await storage.count_reserved())


async def post_shutdown(application: Application) -> None:
    ctx: AppContext | None = application.bot_data.get("ctx")
    if ctx is None:
        return
    if ctx.hunter.running:
        await ctx.hunter.stop()
    await ctx.mws.__aexit__()
    await ctx.storage.close()


def main() -> None:
    settings = Settings.from_env()
    setup_logging(settings)

    if not settings.telegram_bot_token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN is not set")
    if not settings.telegram_allowed_chat_ids:
        logger.warning("TELEGRAM_ALLOWED_CHAT_IDS is empty -- the bot will ignore every chat")

    application = (
        ApplicationBuilder()
        .token(settings.telegram_bot_token)
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )
    application.bot_data["settings"] = settings
    register_handlers(application)

    logger.info("starting MWS IP-Hunter bot")
    application.run_polling()


if __name__ == "__main__":
    main()
