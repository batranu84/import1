from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse, urlunparse

_NUMERIC = re.compile(r"^\d+$")
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,}$")
_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")


def normalize_path(path: str) -> str:
    parts = []
    for part in path.split("/"):
        if _NUMERIC.match(part):
            parts.append("{id}")
        elif _UUID.match(part):
            parts.append("{uuid}")
        elif _HEX.match(part):
            parts.append("{token}")
        else:
            parts.append(part)
    value = "/".join(parts)
    return value or "/"


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path = normalize_path(parsed.path or "/")
    return urlunparse((parsed.scheme.lower(), parsed.netloc.lower(), path, "", "", ""))


def same_origin(base: str, candidate: str) -> bool:
    a, b = urlparse(base), urlparse(candidate)
    return (a.scheme.lower(), a.hostname, a.port) == (b.scheme.lower(), b.hostname, b.port)


def absolute_url(base: str, href: str) -> str:
    return urljoin(base, href)
