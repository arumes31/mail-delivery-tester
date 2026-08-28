"""Bounded HTTPS helpers used by the imported header decoder."""

from __future__ import annotations

from urllib.parse import urlsplit

import requests

DEFAULT_TIMEOUT = (3.05, 10)
DEFAULT_MAX_BYTES = 512 * 1024


def bounded_https_get(url, *, max_bytes=DEFAULT_MAX_BYTES, **kwargs):
    """Fetch a small HTTPS response with connect/read deadlines."""
    if urlsplit(url).scheme != "https":
        raise ValueError("outbound decoder requests must use HTTPS")
    kwargs.pop("stream", None)
    kwargs.setdefault("allow_redirects", False)
    with requests.get(
        url,
        stream=True,
        timeout=DEFAULT_TIMEOUT,
        **kwargs,
    ) as response:
        response.raise_for_status()
        chunks = []
        size = 0
        for chunk in response.iter_content(chunk_size=64 * 1024):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError("outbound response exceeded size limit")
            chunks.append(chunk)
        response._content = b"".join(chunks)
        response._content_consumed = True
        return response
