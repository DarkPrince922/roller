"""MWS (MTS Web Services) cloud API client -- public IP create/get/list/delete,
plus IAM service-account token issuance.

Confirmed against the official OpenAPI specs and reference Go SDK at
https://github.com/mws-cloud-platform/api and https://github.com/mws-cloud-platform/go-sdk
at the time this was written:

  * IAM gateway: https://iam.mwsapis.ru -- service-account-key-to-access-token exchange.
    Auth for resource calls: `Authorization: Bearer <IAM access token>`. The access
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
         `Bearer` token for all other mws-cloud-platform services, and must be
         refreshed before expiry.
    This is implemented below (`ServiceAccountKey` + `MwsClient._ensure_token`). A
    static long-lived `MWS_API_TOKEN` is still supported as a manual-override fallback
    for cases where the caller already has a valid access token and doesn't want to
    configure a service-account key -- but it is NOT auto-refreshed and will expire.

  * Resource gateway for public IPs: https://vpc.mwsapis.ru (the VPC service). Public
    IPv4/IPv6 addresses are modelled as the "external address" resource, per
    `openapi/vpc/openapi.gen.yaml`:
      - `GET    /vpc/v1/projects/{project}/externalAddresses`               (list, paginated)
      - `POST   /vpc/v1/projects/{project}/externalAddresses/{name}`        (create/update --
         "upsert"; `?createOnly=true` makes it fail with `ALREADY_EXISTS` instead of
         updating an existing resource)
      - `GET    /vpc/v1/projects/{project}/externalAddresses/{name}`        (get)
      - `DELETE /vpc/v1/projects/{project}/externalAddresses/{name}`        (delete, 204)
    Unlike a typical POST-to-collection-returns-generated-id flow, `{name}` is chosen
    by the caller (DNS-label-ish: `^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$`) and is the only
    identifier needed for subsequent get/delete -- there is no separate generated
    "service id" to track. Request body shape (`ExternalAddressRequest`):
        {"metadata": {"displayName": ..., "description": ...},
         "spec": {"natGateway": "<optional ref, defaults to natGateways/internet-gateway>"}}
    Response body shape (`ExternalAddressResponse`):
        {"kind": "vpc/v1/externalAddress",
         "metadata": {"id": "vpc/projects/{project}/externalAddresses/{name}", ...},
         "spec": {"natGateway": ...},
         "status": {"ready": {"state": "OK"|"FAILED"|"PROCESSING"}, "ipAddress": "1.2.3.4",
                    "active": true}}
    This resource has no region/zone scoping at the API level -- only `project`.

  * Idempotency: `Idempotency-Key: <uuid4>` header, supported on the create (POST) and
    delete operations.
  * Error body (`ApiError`): {"code": "<ENUM, e.g. QUOTA_EXCEEDED/UNAUTHENTICATED/...>",
    "description": ..., "details": {...}}. Note this has no "domain" field -- a `domain:
    hub` 401 (as originally reported) is NOT from this API; it's a sign requests are
    hitting an unrelated/legacy gateway.

This file previously called a guessed `POST {base}/ocs/v1/services` resource model on
`https://gateway.cloud.mts.ru`, which does not appear anywhere in the official
mws-cloud-platform OpenAPI specs and is almost certainly why every call failed with a
401 from a `hub` auth domain regardless of the IAM token being valid.
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

EXTERNAL_ADDRESS_NAME_PREFIX = "ip-hunter-"

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
_RESOURCE_NAME_RE = re.compile(r"/externalAddresses/(?P<name>[^/]+)$")
_PROJECT_REF_RE = re.compile(r"(?:^|/)projects/(?P<id>[^/]+)$")


def _normalize_project_id(value: str) -> str:
    """Accept either a bare project id or a full resource-manager reference
    (e.g. "rm/projects/<id>", as shown in some MWS console screens) and
    return just the bare id -- the VPC API's {project} path segment always
    expects the bare id, and naively interpolating a full reference there
    doubles up the "projects/" segment (-> 404 "No static resource ...")."""
    match = _PROJECT_REF_RE.search(value)
    return match.group("id") if match else value


class MwsApiError(Exception):
    def __init__(self, kind: str, message: str, status: int | None = None, code: str | None = None):
        super().__init__(message)
        self.kind = kind  # "auth" | "quota" | "rate_limit" | "proxy" | "network" | "server" | "unknown"
        self.status = status
        self.code = code


@dataclass
class ReservedIp:
    service_id: str  # the externalAddress resource name, e.g. "ip-hunter-..."
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


def _generate_address_name() -> str:
    """A name matching the externalAddress path pattern
    ^[a-z]([a-z0-9-]{0,61}[a-z0-9])?$ -- chosen by the caller, not server-generated."""
    return f"{EXTERNAL_ADDRESS_NAME_PREFIX}{uuid.uuid4().hex[:16]}"


def _extract_ip(payload: dict) -> str | None:
    status = payload.get("status")
    if isinstance(status, dict):
        ip = status.get("ipAddress")
        if isinstance(ip, str) and ip:
            return ip
    return None


def _extract_status(payload: dict) -> str:
    status = payload.get("status")
    if isinstance(status, dict):
        ready = status.get("ready")
        if isinstance(ready, dict) and ready.get("state"):
            return str(ready["state"])
    return "unknown"


def _extract_name(payload: dict) -> str | None:
    metadata = payload.get("metadata")
    if not isinstance(metadata, dict):
        return None
    resource_id = metadata.get("id")
    if not isinstance(resource_id, str):
        return None
    match = _RESOURCE_NAME_RE.search(resource_id)
    return match.group("name") if match else None


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

    def _addresses_collection_path(self) -> str:
        project = _normalize_project_id(self._settings.mws_project_id)
        return f"/vpc/v1/projects/{project}/externalAddresses"

    def _address_path(self, name: str) -> str:
        return f"{self._addresses_collection_path()}/{name}"

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
        idempotency_key: bool = False,
    ) -> dict:
        await self._ensure_token()
        url = f"{self._settings.mws_vpc_base}{path}"
        headers = {"Authorization": f"Bearer {self._token}"}
        if idempotency_key:
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
                    if resp.status == 204:
                        return {}
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
        if status in (401, 403) or code in ("UNAUTHENTICATED", "PERMISSION_DENIED"):
            return MwsApiError("auth", message, status, code)
        if status == 429 or code == "TOO_MANY_REQUESTS":
            return MwsApiError("rate_limit", message, status, code)
        if code == "QUOTA_EXCEEDED":
            return MwsApiError("quota", message, status, code)
        if status >= 500 or code in ("INTERNAL", "UNAVAILABLE"):
            return MwsApiError("server", message, status, code)
        return MwsApiError("unknown", message, status, code)

    async def create_ip(self) -> ReservedIp:
        name = _generate_address_name()
        spec: dict[str, Any] = {}
        if self._settings.mws_nat_gateway:
            spec["natGateway"] = self._settings.mws_nat_gateway
        body = {
            "metadata": {"description": "mws-ip-hunter"},
            "spec": spec,
        }
        payload = await self._request(
            "POST", self._address_path(name), json_body=body,
            params={"createOnly": "true"}, idempotency_key=True,
        )
        ip = _extract_ip(payload)
        if ip is None:
            ip = await self._poll_for_ip(name)
        return ReservedIp(service_id=name, ip=ip, status=_extract_status(payload),
                           region=self._settings.mws_region)

    async def _poll_for_ip(self, name: str, timeout_sec: float = 30.0, interval_sec: float = 2.0) -> str | None:
        elapsed = 0.0
        while elapsed < timeout_sec:
            payload = await self.get_service(name)
            ip = _extract_ip(payload)
            if ip:
                return ip
            await asyncio.sleep(interval_sec)
            elapsed += interval_sec
        logger.error("timed out waiting for IP assignment on external address %s", name)
        return None

    async def get_service(self, name: str) -> dict:
        return await self._request("GET", self._address_path(name))

    async def list_ip_services(self) -> list[ReservedIp]:
        result: list[ReservedIp] = []
        page_token: str | None = None
        while True:
            params: dict[str, Any] = {"pageSize": 200}
            if page_token:
                params["pageToken"] = page_token
            payload = await self._request("GET", self._addresses_collection_path(), params=params)
            items = payload.get("items") if isinstance(payload, dict) else None
            if not isinstance(items, list):
                break
            for item in items:
                name = _extract_name(item)
                if not name:
                    continue
                result.append(ReservedIp(
                    service_id=name, ip=_extract_ip(item), status=_extract_status(item),
                    region=self._settings.mws_region,
                ))
            page_token = payload.get("nextPageToken")
            if not page_token:
                break
        return result

    async def delete_service(self, service_id: str) -> None:
        try:
            await self._request("DELETE", self._address_path(service_id), idempotency_key=True)
        except MwsApiError as exc:
            if exc.status in (404, 410) or exc.code == "NOT_FOUND":
                return  # already gone -- delete is idempotent
            raise
