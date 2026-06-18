"""Shared application context wired up once in main.py and stashed in
Application.bot_data so every handler can reach storage/hunter/mws client."""
from __future__ import annotations

from app.asn_resolver import AsnResolver
from app.config import Settings
from app.hunter import Hunter
from app.mws_client import MwsClient
from app.proxy import ProxyConfig, build_connector
from app.storage import Storage


class AppContext:
    def __init__(self, settings: Settings, storage: Storage, resolver: AsnResolver,
                 mws: MwsClient, hunter: Hunter, proxy_raw: str):
        self.settings = settings
        self.storage = storage
        self.resolver = resolver
        self.mws = mws
        self.hunter = hunter
        self.proxy_raw = proxy_raw

    async def rebuild_mws_client(self, new_proxy_raw: str) -> None:
        proxy_cfg = ProxyConfig.parse(new_proxy_raw) if new_proxy_raw else None
        connector = build_connector(proxy_cfg)
        new_client = MwsClient(self.settings, connector)
        await new_client.__aenter__()
        old_client = self.mws
        self.mws = new_client
        self.hunter.mws = new_client
        await old_client.__aexit__()
        self.proxy_raw = new_proxy_raw
