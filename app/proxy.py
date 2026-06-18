"""SOCKS5 proxy string parsing (`host:port:user:pass` or `host:port`) and
aiohttp connector construction."""
from __future__ import annotations

from dataclasses import dataclass

from aiohttp_socks import ProxyConnector


@dataclass(frozen=True)
class ProxyConfig:
    host: str
    port: int
    username: str | None = None
    password: str | None = None

    @classmethod
    def parse(cls, raw: str) -> "ProxyConfig":
        raw = raw.strip()
        if not raw:
            raise ValueError("empty proxy string")
        # split on first 3 ':' only -- password may itself contain ':'
        parts = raw.split(":", 3)
        if len(parts) == 2:
            host, port = parts
            return cls(host=host, port=int(port))
        if len(parts) == 4:
            host, port, user, password = parts
            return cls(host=host, port=int(port), username=user or None, password=password or None)
        raise ValueError(
            "proxy must be 'host:port' or 'host:port:user:pass', got "
            f"{len(parts)} colon-separated parts"
        )

    def to_url(self) -> str:
        auth = ""
        if self.username is not None:
            auth = f"{self.username}:{self.password or ''}@"
        return f"socks5://{auth}{self.host}:{self.port}"

    def masked(self) -> str:
        if self.username is None:
            return f"{self.host}:{self.port}"
        return f"{self.host}:{self.port}:{self.username}:***"


def build_connector(proxy: ProxyConfig | None) -> ProxyConnector | None:
    if proxy is None:
        return None
    return ProxyConnector.from_url(proxy.to_url())
