"""Target matching: an IP matches if it falls in any configured CIDR OR
belongs to any configured ASN. Pure, local, instant -- no I/O."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field


@dataclass
class TargetConfig:
    cidrs: list[str] = field(default_factory=list)
    asns: set[int] = field(default_factory=set)

    def to_dict(self) -> dict:
        return {"cidrs": self.cidrs, "asns": sorted(self.asns)}

    @classmethod
    def from_dict(cls, data: dict) -> "TargetConfig":
        return cls(cidrs=list(data.get("cidrs", [])), asns=set(data.get("asns", [])))

    @property
    def is_empty(self) -> bool:
        return not self.cidrs and not self.asns


def matches(ip: str, asn: int | None, target: TargetConfig) -> bool:
    if target.is_empty:
        return False
    if target.cidrs:
        addr = ipaddress.ip_address(ip)
        for cidr in target.cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
    if asn is not None and asn in target.asns:
        return True
    return False
