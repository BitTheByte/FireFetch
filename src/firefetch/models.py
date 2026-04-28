from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class FirebaseCreds:
    project_id: str | None = None
    google_app_id: str | None = None
    api_key: str | None = None
    database_url: str | None = None
    storage_bucket: str | None = None
    gcm_sender_id: str | None = None
    web_client_id: str | None = None
    extra_api_keys: list[str] = field(default_factory=list)
    extra_app_ids: list[str] = field(default_factory=list)
    extra_oauth_clients: list[str] = field(default_factory=list)
    fcm_server_key: str | None = None
    android_package: str | None = None
    android_cert_sha1: str | None = None

    @property
    def has_minimum(self) -> bool:
        return bool(self.project_id or self.google_app_id)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeResult:
    name: str
    status: str
    detail: str = ""
    data: Any = None
    url: str | None = None
    api_key: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "detail": self.detail,
            "url": self.url,
            "data": self.data,
            "api_key": self.api_key,
        }
