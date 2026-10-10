from unittest.mock import Mock, patch

import pytest

from http_utils import bounded_https_get


def response_with(chunks):
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.iter_content.return_value = chunks
    response.raise_for_status.return_value = None
    return response


def test_bounded_get_requires_https():
    with pytest.raises(ValueError, match="HTTPS"):
        bounded_https_get("http://example.com")


@patch("http_utils.requests.get")
def test_bounded_get_sets_deadlines_disables_redirects_and_limits_size(get):
    get.return_value = response_with([b"abc", b"def"])
    response = bounded_https_get("https://example.com", max_bytes=6)
    assert response._content == b"abcdef"
    assert get.call_args.kwargs["timeout"] == (3.05, 10)
    assert get.call_args.kwargs["allow_redirects"] is False
    assert get.call_args.kwargs["stream"] is True


@patch("http_utils.requests.get")
def test_bounded_get_rejects_oversized_response(get):
    get.return_value = response_with([b"abcd", b"efgh"])
    with pytest.raises(ValueError, match="size limit"):
        bounded_https_get("https://example.com", max_bytes=7)
