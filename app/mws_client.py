"""MWS (MTS Web Services) cloud API client -- public IP create/get/list/delete,
plus IAM service-account token issuance.

Confirmed against the public docs at https://docs.cloud.mts.ru/api/ (auth.html,
errors.html, open-api-computecloud.html) and the official OpenAPI specs/SDK at
https://github.com/mws-cloud-platform/api and https://github.com/mws-cloud-platform/go-sdk
at the time this was written:

  * Resource gateway: https://gateway.cloud.mts.ru
  * IAM gateway: https://iam.mwsapis.ru (separate host from the resource gateway).
  * Auth for resource calls: `Authorization: Bearer <IAM access token>`. The access
    token is short-lived and must be obtained by exchanging a service account's
    "authorized key" (an ES256 keypair, created in the console under IAM / Сервисные
    аккаунты) for a token:
      1. Build a JWT assertion: header `{"alg": "ES256", "kid": "<authorizedKey id>"}`,
         payload `{"sub": "projects/<project>/serviceAccounts/<sa>", "iat": ..., "exp": ...}`,
         signed with the authorized key's ES256 private key.
      2. `GET {iam_base}/iam/v2/tokens/:issueServiceAccountToken?serviceAccount=<sub>`
         with header `Authorization: <raw signed JWT>` (note: no "Bearer " prefix --
         confirmed against go-sdk's `headerIssueServiceAccountTokenV2`, which sets the
         header to the signed JWS verbatim).
      3. Response is `{"accessToken": "...", "expirationTs": "<RFC3339>"}` (`accessToken`
         is the only required field). That `accessToken` is the value used as the
         `Bearer` token for the resource gateway, and must be refreshed before expiry.
    This is implemented below (`ServiceAccountKey` + `MwsClient._ensure_token`). A
    static long-lived `MWS_API_TOKEN` is still supported as a manual-override fallback
    for cases where the caller already has a valid access token and doesn't want to
    configure a service-account key -- but it is NOT auto-refreshed and will expire.
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
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import aiohttp
import jwt
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from cryptography.hazmat.primitives.serialization import load_der_private_key

from app.config import Settings

logger = logging.getLogger(__name__)

CREATE_PATH = "/ocs/v1/services"
PRODUCT_CODE = "network"
RESOURCE_KIND = "ip"

IAM_TOKEN_PATH = "/iam/v2/tokens/:issueServiceAccountToken"
JWT_ALG = "ES256"
JWT_ASSERTION_TTL_SEC = 3600
DEFAULT_ACCESS_TOKEN_TTL_SEC = 3000  # used only if the IAM response omits expirationTs
TOKEN_REFRESH_SKEW_SEC = 60

RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
MAX_RETRIES = 5
BACKOFF_BASE_SEC = 1.0

_AUTHORIZED_KEY_ID_RE = re.compile(
    r"^projects/(?P<project>[^/]+)/serviceAccounts/(?P<service_account>[^/]+)"
    r"/authorizedKeys/(?P<key>[^/]+)$"
)


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


@dataclass
class ServiceAccountKey:
    """A service account's authorized key, as downloaded from the MWS console
    (IAM / Сервисные аккаунты / authorized key JSON). Field names below match
    that JSON file: {"keyId": "projects/.../authorizedKeys/...", "privateKey":
    "<base64 PKCS8 DER>", "publicKey": "...", "algorithm": "ES256"}."""

    project: str
    service_account: str
    key_id: str
    private_key: EllipticCurvePrivateKey

    @property
    def service_account_ref(self) -> str:
        return f"projects/{self.project}/serviceAccounts/{self.service_account}"

    @classmethod
    def load(cls, path: Path) -> "ServiceAccountKey":
        data = json.loads(path.read_text())
        full_key_id = data["keyId"]
        match = _AUTHORIZED_KEY_ID_RE.match(full_key_id)
        if not match:
            raise ValueError(
                f"unexpected keyId format in {path}: {full_key_id!r} "
                "(expected projects/<project>/serviceAccounts/<sa>/authorizedKeys/<key>)"
            )
        algorithm = data.get("algorithm")
        if algorithm and algorithm != JWT_ALG:
            raise ValueError(f"unsupported authorized key algorithm in {path}: {algorithm!r}")
        der = base64.b64decode(data["privateKey"])
        private_key = load_der_private_key(der, password=None)
        if not isinstance(private_key, EllipticCurvePrivateKey):
            raise ValueError(f"private key in {path} is not an EC key")
        return cls(
            project=match["project"],
            service_account=match["service_account"],
            key_id=match["key"],
            private_key=private_key,
        )


def _build_assertion(key: ServiceAccountKey) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": key.service_account_ref,
        "iat": now,
        "exp": now + timedelta(seconds=JWT_ASSERTION_TTL_SEC),
    }
    return jwt.encode(payload, key.private_key, algorithm=JWT_ALG, headers={"kid": key.key_id})


def _parse_iso8601(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


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
        self._token_expiry: datetime | None = None
        self._token_lock = asyncio.Lock()
        self._sa_key: ServiceAccountKey | None = None
        if settings.mws_sa_key_file is not None:
            self._sa_key = ServiceAccountKey.load(settings.mws_sa_key_file)

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

    async def _ensure_token(self) -> None:
        """Make sure self._token holds a non-expired IAM access token. No-op in
        static-token mode (no service account key configured)."""
        if self._sa_key is None:
            return
        if self._token and self._token_expiry and \
                datetime.now(timezone.utc) < self._token_expiry - timedelta(seconds=TOKEN_REFRESH_SKEW_SEC):
            return
        async with self._token_lock:
            if self._token and self._token_expiry and \
                    datetime.now(timezone.utc) < self._token_expiry - timedelta(seconds=TOKEN_REFRESH_SKEW_SEC):
                return
            await self._refresh_token_via_iam()

    async def _refresh_token_via_iam(self) -> None:
        assert self._sa_key is not None
        assertion = _build_assertion(self._sa_key)
        url = f"{self._settings.mws_iam_base}{IAM_TOKEN_PATH}"
        headers = {"Authorization": assertion}
        params = {"serviceAccount": self._sa_key.service_account_ref}
        body = await self._send("GET", url, headers=headers, params=params)
        token = body.get("accessToken")
        if not token:
            raise MwsApiError("auth", f"IAM token response missing accessToken: {body}")
        self._token = token
        expiration_ts = body.get("expirationTs")
        if expiration_ts:
            try:
                self._token_expiry = _parse_iso8601(expiration_ts)
            except ValueError:
                logger.warning("could not parse IAM token expirationTs %r, using default TTL", expiration_ts)
                self._token_expiry = None
        if self._token_expiry is None:
            self._token_expiry = datetime.now(timezone.utc) + timedelta(seconds=DEFAULT_ACCESS_TOKEN_TTL_SEC)

    async def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: dict | None = None,
        params: dict | None = None,
        idempotent_create: bool = False,
    ) -> dict:
        await self._ensure_token()
        url = f"{self._settings.mws_api_base}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        if idempotent_create:
            headers["Idempotency-Key"] = str(uuid.uuid4())
        return await self._send(method, url, headers=headers, json_body=json_body, params=params)

    async def _send(
        self,
        method: str,
        url: str,
        *,
        headers: dict,
        json_body: dict | None = None,
        params: dict | None = None,
    ) -> dict:
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
                                       method, url, resp.status, attempt, MAX_RETRIES, delay)
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
                                   method, url, exc, attempt, MAX_RETRIES, delay)
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
