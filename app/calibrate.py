"""Calibration: reserve N addresses (capped at quota), look at the order they
came back in and decide whether MWS hands out addresses sequentially,
clustered within a narrow pool, or scattered randomly -- then recommend a
hunt strategy. All calibration reservations are released again afterward
(unless one of them happens to match the current target, in which case it's
kept, same as a normal hunt hit)."""
from __future__ import annotations

import ipaddress
import statistics
from dataclasses import dataclass

from app.matcher import TargetConfig, matches
from app.mws_client import MwsApiError, MwsClient
from app.storage import Storage

VERDICT_SEQUENTIAL = "sequential"
VERDICT_CLUSTERED = "clustered"
VERDICT_RANDOM = "random"

RECOMMENDATION = {
    VERDICT_SEQUENTIAL: "hold_window",
    VERDICT_CLUSTERED: "hold_window",
    VERDICT_RANDOM: "release_immediately",
}


@dataclass
class CalibrationResult:
    ips: list[str]
    verdict: str
    recommendation: str
    median_delta: float
    distinct_slash24: int


async def run(mws: MwsClient, storage: Storage, target: TargetConfig, quota: int, n: int) -> CalibrationResult:
    n = max(2, min(n, quota))
    reserved: list[tuple[str, str]] = []  # (service_id, ip)
    try:
        for _ in range(n):
            res = await mws.create_ip()
            if res.ip:
                reserved.append((res.service_id, res.ip))
    finally:
        result = _analyze([ip for _, ip in reserved])
        for service_id, ip in reserved:
            is_target = matches(ip, None, target)
            if is_target:
                await storage.add_reserved(service_id, ip, "kept", None)
            else:
                try:
                    await mws.delete_service(service_id)
                except MwsApiError:
                    pass
        await storage.set_config_json("calibration_result", {
            "ips": result.ips, "verdict": result.verdict, "recommendation": result.recommendation,
            "median_delta": result.median_delta, "distinct_slash24": result.distinct_slash24,
        })
    return result


def _analyze(ips: list[str]) -> CalibrationResult:
    if len(ips) < 2:
        return CalibrationResult(ips=ips, verdict=VERDICT_RANDOM, recommendation=RECOMMENDATION[VERDICT_RANDOM],
                                  median_delta=0.0, distinct_slash24=len(ips))

    ints = [int(ipaddress.ip_address(ip)) for ip in ips]
    deltas = [b - a for a, b in zip(ints, ints[1:])]
    abs_deltas = [abs(d) for d in deltas]
    median_delta = statistics.median(abs_deltas)
    slash24s = {int(ipaddress.ip_address(ip)) >> 8 for ip in ips}
    distinct_slash24 = len(slash24s)

    monotonic_fraction = sum(1 for d in deltas if d > 0) / len(deltas)

    if median_delta < 256 and monotonic_fraction >= 0.7:
        verdict = VERDICT_SEQUENTIAL
    elif distinct_slash24 <= max(1, len(ips) // 3):
        verdict = VERDICT_CLUSTERED
    else:
        verdict = VERDICT_RANDOM

    return CalibrationResult(
        ips=ips, verdict=verdict, recommendation=RECOMMENDATION[verdict],
        median_delta=median_delta, distinct_slash24=distinct_slash24,
    )
