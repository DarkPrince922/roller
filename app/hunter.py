"""The hunt engine: reserve -> resolve -> match -> release/keep loop, strategies,
dedup, budget/stop-condition tracking. Notifies the bot layer via an injected
async callback instead of importing anything telegram-specific."""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Awaitable, Callable

from app.asn_resolver import AsnResolver, ResolveResult
from app.matcher import TargetConfig, matches
from app.mws_client import MwsApiError, MwsClient
from app.storage import Storage

logger = logging.getLogger(__name__)

Notifier = Callable[[str, dict], Awaitable[None]]

STRATEGY_RELEASE_IMMEDIATELY = "release_immediately"
STRATEGY_HOLD_WINDOW = "hold_window"
PROGRESS_EVERY_N_ATTEMPTS = 25


class StopReason(str, Enum):
    TARGET_REACHED = "target_reached"
    MAX_ATTEMPTS = "max_attempts"
    MAX_RUNTIME = "max_runtime"
    MAX_BUDGET = "max_budget"
    MANUAL = "manual"
    ERROR = "error"


class AlreadyRunning(Exception):
    pass


@dataclass
class HuntLimits:
    strategy: str = STRATEGY_RELEASE_IMMEDIATELY
    target: TargetConfig = field(default_factory=TargetConfig)
    target_count: int = 1
    max_attempts: int = 500
    max_runtime_min: int = 120
    max_budget: float = 0.0
    rate_limit_delay_sec: float = 2.0
    estimated_cost_per_ip_hour: float = 0.0
    quota: int = 5


@dataclass
class HuntStats:
    attempts: int = 0
    unique: int = 0
    rerolls: int = 0
    found: int = 0
    started_at: float | None = None

    def elapsed_min(self) -> float:
        if self.started_at is None:
            return 0.0
        return (time.monotonic() - self.started_at) / 60.0


class Hunter:
    def __init__(self, storage: Storage, mws: MwsClient, resolver: AsnResolver,
                 limits: HuntLimits, notifier: Notifier):
        self.storage = storage
        self.mws = mws
        self.resolver = resolver
        self.limits = limits
        self.notifier = notifier
        self.stats = HuntStats()
        self.running = False
        self._stop_event = asyncio.Event()
        self._task: asyncio.Task | None = None

    # ---- lifecycle ----

    async def sync_from_api(self) -> None:
        """Pull real reservation state from MWS on startup so we never exceed quota
        because of state lost across a restart."""
        try:
            live = await self.mws.list_ip_services()
        except MwsApiError as exc:
            logger.error("could not sync reservations from MWS on startup: %s", exc)
            return
        for item in live:
            await self.storage.add_reserved(item.service_id, item.ip, "kept" if item.status != "unknown" else "pending", item.region)

    async def start(self) -> None:
        if self.running:
            raise AlreadyRunning()
        self._stop_event.clear()
        self.stats = HuntStats(started_at=time.monotonic())
        self.running = True
        self._task = asyncio.create_task(self._run())

    async def stop(self, release_misses: bool = False) -> None:
        self._stop_event.set()
        if self._task is not None:
            await self._task
        if release_misses:
            for rec in await self.storage.list_reserved(status="held"):
                await self.release(rec.service_id)

    # ---- main loop ----

    async def _run(self) -> None:
        reason = StopReason.MANUAL
        try:
            while True:
                stop = self._check_stop_conditions()
                if stop is not None:
                    reason = stop
                    break

                if await self.storage.count_reserved() >= self.limits.quota:
                    candidate = await self._pick_release_candidate()
                    if candidate is not None:
                        await self.release(candidate)

                await self._attempt_once()
                await asyncio.sleep(self.limits.rate_limit_delay_sec)
        except asyncio.CancelledError:
            reason = StopReason.MANUAL
        except Exception:
            logger.exception("hunt loop crashed")
            reason = StopReason.ERROR
            await self.notifier("error", {"message": "hunt loop crashed, see logs"})
        finally:
            self.running = False
            await self.notifier("stop", {"reason": reason.value, "stats": self.stats})

    def _check_stop_conditions(self) -> StopReason | None:
        if self._stop_event.is_set():
            return StopReason.MANUAL
        if self.stats.found >= self.limits.target_count:
            return StopReason.TARGET_REACHED
        if self.stats.attempts >= self.limits.max_attempts:
            return StopReason.MAX_ATTEMPTS
        if self.stats.elapsed_min() >= self.limits.max_runtime_min:
            return StopReason.MAX_RUNTIME
        if self.limits.max_budget > 0 and self.estimated_cost() >= self.limits.max_budget:
            return StopReason.MAX_BUDGET
        return None

    def estimated_cost(self) -> float:
        # Rough estimate only -- real billing unit unconfirmed, see mws_client.py docstring.
        hours = self.stats.elapsed_min() / 60.0
        return hours * self.limits.estimated_cost_per_ip_hour * self.limits.quota

    async def _attempt_once(self) -> None:
        try:
            reserved = await self.mws.create_ip()
        except MwsApiError as exc:
            await self.notifier("error", {"message": str(exc), "kind": exc.kind})
            if exc.kind == "quota":
                # The real account-side quota may be lower than self.limits.quota
                # (the pre-check in _run() only guards against the configured value),
                # so a quota error here doesn't necessarily mean we're stuck -- free up
                # the oldest non-target reservation and let the loop retry.
                candidate = await self._pick_release_candidate()
                if candidate is not None:
                    await self.release(candidate)
                    return
                self._stop_event.set()
            elif exc.kind == "auth":
                self._stop_event.set()
            return

        if reserved.ip is None:
            await self.notifier("error", {"message": f"service {reserved.service_id} got no IP, releasing"})
            await self.release(reserved.service_id)
            return

        ip = reserved.ip
        self.stats.attempts += 1

        pre_existing = await self.storage.get_seen(ip)
        if pre_existing is None:
            resolved = await self.resolver.resolve(ip, self.mws.session)
        else:
            resolved = ResolveResult(asn=pre_existing.asn, prefix=pre_existing.prefix, as_name=pre_existing.as_name)

        is_target = matches(ip, resolved.asn, self.limits.target)
        await self.storage.upsert_seen(ip, resolved.asn, resolved.prefix, resolved.as_name, is_target)
        await self.storage.log_attempt(ip, resolved.asn, resolved.prefix, is_target)

        if pre_existing is not None:
            self.stats.rerolls += 1
            await self.storage.add_reserved(reserved.service_id, ip, "pending", reserved.region)
            await self.release(reserved.service_id)
            self._maybe_progress()
            return

        self.stats.unique += 1

        if is_target:
            self.stats.found += 1
            await self.storage.add_reserved(reserved.service_id, ip, "kept", reserved.region)
            await self.notifier("hit", {
                "ip": ip, "asn": resolved.asn, "prefix": resolved.prefix,
                "as_name": resolved.as_name, "service_id": reserved.service_id,
            })
        else:
            if self.limits.strategy == STRATEGY_HOLD_WINDOW:
                await self.storage.add_reserved(reserved.service_id, ip, "held", reserved.region)
            else:
                await self.storage.add_reserved(reserved.service_id, ip, "pending", reserved.region)
                await self.release(reserved.service_id)

        self._maybe_progress()

    def _maybe_progress(self) -> None:
        if self.stats.attempts and self.stats.attempts % PROGRESS_EVERY_N_ATTEMPTS == 0:
            asyncio.create_task(self.notifier("progress", {"stats": self.stats}))

    async def _pick_release_candidate(self) -> str | None:
        held = await self.storage.list_reserved(status="held")
        if held:
            return held[0].service_id  # FIFO -- oldest first
        pending = await self.storage.list_reserved(status="pending")
        if pending:
            return pending[0].service_id
        return None  # only "kept" targets remain -- nothing safe to release

    async def release(self, service_id: str) -> None:
        try:
            await self.mws.delete_service(service_id)
        except MwsApiError as exc:
            await self.notifier("error", {"message": f"failed to release {service_id}: {exc}", "kind": exc.kind})
            return
        await self.storage.remove_reserved(service_id)
