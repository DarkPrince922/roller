"""IP -> ASN/prefix/AS-name resolution.

Primary source: a local ip2asn TSV (https://iptoasn.com/, columns
range_start, range_end, asn, country, as_name), loaded fully into memory and
queried with bisect -- no network call, no rate limit, works offline.

Fallback (only used when the local DB is missing the range, or wasn't loaded
at all): RIPEstat's public network-info API. This is network-dependent and
should not be relied on for high-throughput hunting -- it exists so the tool
still works before the operator has downloaded the ip2asn dataset.
"""
from __future__ import annotations

import bisect
import ipaddress
import logging
from dataclasses import dataclass
from pathlib import Path

import aiohttp

logger = logging.getLogger(__name__)

RIPESTAT_URL = "https://stat.ripe.net/data/network-info/data.json"


@dataclass
class ResolveResult:
    asn: int | None
    prefix: str | None
    as_name: str | None


def _ip_to_int(ip: str) -> int:
    return int(ipaddress.ip_address(ip))


class AsnResolver:
    def __init__(self, tsv_path: Path):
        self._tsv_path = tsv_path
        self._starts: list[int] = []
        self._ranges: list[tuple[int, int, int, str]] = []  # start, end, asn, as_name
        self._loaded = False

    @property
    def loaded(self) -> bool:
        return self._loaded

    def load(self) -> int:
        """Parse the TSV into memory. Returns the number of ranges loaded.
        Safe to call when the file doesn't exist -- resolver just falls back
        to the network lookup for every query."""
        if not self._tsv_path.exists():
            logger.warning("ip2asn db not found at %s, falling back to RIPEstat for all lookups", self._tsv_path)
            return 0

        ranges: list[tuple[int, int, int, str]] = []
        with self._tsv_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 5:
                    continue
                start_ip, end_ip, asn_str, _country, as_name = parts[:5]
                try:
                    asn = int(asn_str)
                except ValueError:
                    continue
                if asn == 0:
                    continue  # unallocated/unrouted range
                ranges.append((_ip_to_int(start_ip), _ip_to_int(end_ip), asn, as_name))

        ranges.sort(key=lambda r: r[0])
        self._ranges = ranges
        self._starts = [r[0] for r in ranges]
        self._loaded = True
        logger.info("loaded %d ip2asn ranges from %s", len(ranges), self._tsv_path)
        return len(ranges)

    def resolve_local(self, ip: str) -> ResolveResult | None:
        if not self._ranges:
            return None
        ip_int = _ip_to_int(ip)
        idx = bisect.bisect_right(self._starts, ip_int) - 1
        if idx < 0:
            return None
        start, end, asn, as_name = self._ranges[idx]
        if not (start <= ip_int <= end):
            return None
        prefix = _summarize_containing(ip, start, end)
        return ResolveResult(asn=asn, prefix=prefix, as_name=as_name)

    async def resolve(self, ip: str, session: aiohttp.ClientSession) -> ResolveResult:
        local = self.resolve_local(ip)
        if local is not None:
            return local
        return await self._resolve_ripestat(ip, session)

    async def _resolve_ripestat(self, ip: str, session: aiohttp.ClientSession) -> ResolveResult:
        try:
            async with session.get(RIPESTAT_URL, params={"resource": ip}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                data = await resp.json()
            payload = data.get("data", {})
            asns = payload.get("asns") or []
            asn = int(asns[0]) if asns else None
            prefix = payload.get("prefix")
            return ResolveResult(asn=asn, prefix=prefix, as_name=None)
        except Exception:
            logger.exception("RIPEstat fallback lookup failed for %s", ip)
            return ResolveResult(asn=None, prefix=None, as_name=None)


def _summarize_containing(ip: str, start_int: int, end_int: int) -> str:
    """Smallest CIDR block (from the summarized range) that actually contains `ip`."""
    try:
        start = ipaddress.ip_address(start_int)
        end = ipaddress.ip_address(end_int)
        addr = ipaddress.ip_address(ip)
        for net in ipaddress.summarize_address_range(start, end):
            if addr in net:
                return str(net)
    except ValueError:
        pass
    return f"{ipaddress.ip_address(start_int)}-{ipaddress.ip_address(end_int)}"
