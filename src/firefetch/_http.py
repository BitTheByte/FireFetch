from __future__ import annotations

import os

_PROXY: str | None = None
_VERIFY: bool = True


def configure(proxy: str | None, insecure: bool) -> None:
    global _PROXY, _VERIFY
    _PROXY = proxy
    _VERIFY = not insecure

    if proxy:
        os.environ["HTTP_PROXY"] = proxy
        os.environ["HTTPS_PROXY"] = proxy

    if insecure:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        import requests

        original = requests.Session.request

        def patched(self, method, url, **kwargs):
            kwargs.setdefault("verify", False)
            return original(self, method, url, **kwargs)

        requests.Session.request = patched  # type: ignore[assignment]


def proxy() -> str | None:
    return _PROXY


def verify() -> bool:
    return _VERIFY
