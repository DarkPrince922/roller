"""MWS (MTS Web Services) cloud API client -- public IP create/get/list/delete.

Confirmed against the public docs at https://docs.cloud.mts.ru/api/ (auth.html,
errors.html, open-api-computecloud.html) at the time this was written:

  * Base gateway: https://gateway.cloud.mts.ru
  * Auth: `Authorization: Bearer <token>`. A service-account token is generated
    via the console/IAM and can be long-lived -- that's the supported path here
    (MWS_API_TOKEN). Auto-refresh via POST /iam/v2/tokens exists in MWS but the
    exact request body wasn't confirmed -- see `_TODO_refresh_via_iam` below.
  * Idempotency: `Idempotency-Key: <uuid4>` header on resource-creation requests.
  * Generic resource model: POST {base}/ocs/v1/services with
      {"platform": {"productCode": "network", "regionCode": ...},
       "kind": "ip", "metadata": {...}, "parentBinding": {"targetId": <networkId>},
       "projectId": ..., "spec": {}, "zoneCode": ...}
  * Error body: {"code": ..., "domain": ..., "details": {...}}.

NOT independently confirmed -- marked TODO, verify against the live OpenAPI spec
before relying on them in production:
  * Exact JSON path of the assigned IP address in the create/get response.
  * Query params for listing existing services filtered by kind=ip.
  * Whether DELETE returns the IP to the pool immediately or with a delay.
  * /iam/v2/tokens request/response body for auto-refresh.
"""
from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass
from typing import Any

import aiohttp

from app.config import Settings

logger = logging.getLogger(__name__)

CREATE_PATH = "/ocs/v1/services"
PRODUCT_CODE = "network"
RESOURCE_KIND = "ip"

RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRIES = 5
BACKOFF_BASE_SEC = 1.0


class MwsApiError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.kind = kind  # "auth" | "quota" | "proxy" | "network" | "server" | "unknown"
        self.status = status
        self.code = code


@dataclass
class ReservedIp:
    service_id: str
    ip: str | None
    status: str
    region: str | None


def _extract_ip(payload: dict) -> str | None:
    """Best-effort extraction of the assigned address from a service payload.
    Response field names are unconfirmed (see module docstring) -- this tries
    the shapes seen in other MWS OpenAPI examples (spec.* / status.*) before
    giving up. Tighten this once a real response has been observed."""
    candidates = [
        ("spec", "address"),
        ("status", "address"),
        ("spec", "ip"),
        ("status", "ip"),
        ("address",),
        ("ip",),
    ]
    for path in candidates:
        node: Any = payload
        for key in path:
            if not isinstance(node, dict) or key not in node:
                node = None
                break
            node = node[key]
        if isinstance(node, str) and node:
            return node
    return None


def _extract_status(payload: dict) -> str:
    status = payload.get("status")
    if isinstance(status, dict):
        return str(status.get("phase") or status.get("state") or "unknown")
    if isinstance(status, str):
        return status
    return "unknown"


class MwsClient:
    def __init__(self, settings: Settings, connector: aiohttp.BaseConnector | None):
        self._settings = settings
        self._connector = connector
        self._session: aiohttp.ClientSession | None = None
        self._token = settings.mws_api_token

    async def __aenter__(self) -> "MwsClient":
        self._session = aiohttp.ClientSession(connector=self._connector)
        return self

    async def __aexit__(self, *exc) -> None:
        if self._session is not None:
            await self._session.close()

    @property
    def session(self) -> aiohttp.ClientSession:
        assert self._session is not None, "use 'async with MwsClient(...)'"
        return self._session

    def set_token(self, token: str) -> None:
        self._token = token

    async def _TODO_refresh_via_iam(self) -> str:
        """TODO: confirm request body against /iam/v2/tokens before enabling.
        Not called anywhere by default -- MWS_API_TOKEN is used as-is."""
        raise NotImplementedError(
            "IAM token auto-refresh is not confirmed against the live MWS OpenAPI "
            "spec yet; set a long-lived MWS_API_TOKEN instead."
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
        idempotent_create: bool = False,
    ) -> dict:
        url = f"{self._settings.mws_api_base}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        if idempotent_create:
            headers["Idempotency-Key"] = str(uuid.uuid4())

        attempt = 0
        while True:
            attempt += 1
            try:
                async with self.session.request(
                    method, url, json=json_body, params=params, headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status in RETRYABLE_STATUSES and attempt <= MAX_RETRIES:
                        delay = BACKOFF_BASE_SEC * (2 ** (attempt - 1))
                        logger.warning("MWS API %s %s -> %s, retry %d/%d in %.1fs",
                                       method, path, resp.status, attempt, MAX_RETRIES, delay)
                        await asyncio.sleep(delay)
                        continue
                    body = await self._read_json(resp)
                    if resp.status >= 400:
                        raise self._classify_error(resp.status, body)
                    return body
            except MwsApiError:
                raise
            except (aiohttp.ClientProxyConnectionError,) as exc:
                raise MwsApiError("proxy", f"proxy connection failed: {exc}") from exc
            except (aiohttp.ClientConnectorError, asyncio.TimeoutError, aiohttp.ServerTimeoutError) as exc:
                if attempt <= MAX_RETRIES:
                    delay = BACKOFF_BASE_SEC * (2 ** (attempt - 1))
                    logger.warning("network error on %s %s: %s, retry %d/%d in %.1fs",
                                   method, path, exc, attempt, MAX_RETRIES, delay)
                    await asyncio.sleep(delay)
                    continue
                raise MwsApiError("network", f"network error: {exc}") from exc
            except aiohttp.ClientError as exc:
                raise MwsApiError("network", f"client error: {exc}") from exc

    @staticmethod
    async def _read_json(resp: aiohttp.ClientResponse) -> dict:
        try:
            return await resp.json()
        except (aiohttp.ContentTypeError, ValueError):
            text = await resp.text()
            return {"raw": text}

    @staticmethod
    def _classify_error(status: int, body: dict) -> MwsApiError:
        code = body.get("code") if isinstance(body, dict) else None
        message = f"MWS API error {status}: {body}"
        if status in (401, 403):
            return MwsApiError("auth", message, status, code)
        if status == 429:
            return MwsApiError("rate_limit", message, status, code)
        if status in (402, 409) or (code and "quota" in str(code).lower()):
            return MwsApiError("quota", message, status, code)
        if status >= 500:
            return MwsApiError("server", message, status, code)
        return MwsApiError("unknown", message, status, code)

    async def create_ip(self) -> ReservedIp:
        body = {
            "platform": {"productCode": PRODUCT_CODE, "regionCode": self._settings.mws_region_code},
            "kind": RESOURCE_KIND,
            "metadata": {"description": "mws-ip-hunter", "title": "ip-hunter-probe"},
            "parentBinding": {"targetId": self._settings.mws_network_id},
            "projectId": self._settings.mws_project_id,
            "spec": {},
            "zoneCode": self._settings.mws_zone_code,
        }
        payload = await self._request("POST", CREATE_PATH, json_body=body, idempotent_create=True)
        service_id = payload.get("id") or payload.get("serviceId")
        if not service_id:
            raise MwsApiError("unknown", f"create response had no service id: {payload}")
        ip = _extract_ip(payload)
        if ip is None:
            ip = await self._poll_for_ip(service_id)
        return ReservedIp(service_id=service_id, ip=ip, status=_extract_status(payload),
                           region=self._settings.mws_region)

    async def _poll_for_ip(self, service_id: str, timeout_sec: float = 30.0, interval_sec: float = 2.0) -> str | None:
        elapsed = 0.0
        while elapsed < timeout_sec:
            payload = await self.get_service(service_id)
            ip = _extract_ip(payload)
            if ip:
                return ip
            await asyncio.sleep(interval_sec)
            elapsed += interval_sec
        logger.error("timed out waiting for IP assignment on service %s; raw payload field mapping "
                     "in _extract_ip likely needs updating once a real MWS response is inspected", service_id)
        return None

    async def get_service(self, service_id: str) -> dict:
        return await self._request("GET", f"{CREATE_PATH}/{service_id}")

    async def list_ip_services(self) -> list[ReservedIp]:
        # TODO: confirm filter query params against OpenAPI; projectId + kind is a
        # reasonable guess consistent with the create body shape.
        payload = await self._request(
            "GET", CREATE_PATH, params={"projectId": self._settings.mws_project_id, "kind": RESOURCE_KIND}
        )
        items = payload.get("items") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            return []
        result = []
        for item in items:
            service_id = item.get("id") or item.get("serviceId")
            if not service_id:
                continue
            result.append(ReservedIp(
                service_id=service_id, ip=_extract_ip(item), status=_extract_status(item),
                region=self._settings.mws_region,
            ))
        return result

    async def delete_service(self, service_id: str) -> None:
        try:
            await self._request("DELETE", f"{CREATE_PATH}/{service_id}")
        except MwsApiError as exc:
            if exc.status in (404, 410):
                return  # already gone -- delete is idempotent
            raise
