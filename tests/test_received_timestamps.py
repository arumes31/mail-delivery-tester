import time

import pytest
import tldextract

import decode_spam_headers_official as decoder


@pytest.fixture(params=["UTC", "Europe/Vienna"])
def host_timezone(request, monkeypatch):
    # Production and CI run on Linux. Preserve the decoder's existing rule:
    # omitted offsets use the host zone, including its DST gap/fold behavior.
    try:
        with monkeypatch.context() as local:
            local.setenv("TZ", request.param)
            time.tzset()
            yield request.param
    finally:
        time.tzset()


@pytest.fixture
def analysis(monkeypatch):
    monkeypatch.setitem(decoder.options, "dont_resolve", True)
    offline_suffixes = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)
    monkeypatch.setattr(decoder.tldextract, "extract", offline_suffixes)
    return decoder.SMTPHeadersAnalysis(decoder.Logger())


@pytest.mark.parametrize(
    ("stamp", "utc_expected", "vienna_expected"),
    [
        ("27 Oct 2026 12:00:00 +0100", "2026-10-27 11:00:00+00:00", "2026-10-27 11:00:00+00:00"),
        ("27 Oct 2026 12:00:00 -0400", "2026-10-27 16:00:00+00:00", "2026-10-27 16:00:00+00:00"),
        ("27 Oct 2026 12:00:00 UTC", "2026-10-27 12:00:00+00:00", "2026-10-27 12:00:00+00:00"),
        ("27 Oct 2026 12:00:00", "2026-10-27 12:00:00+00:00", "2026-10-27 11:00:00+00:00"),
        ("29 Mar 2026 02:30:00", "2026-03-29 02:30:00+00:00", "2026-03-29 01:30:00+00:00"),
        ("25 Oct 2026 02:30:00", "2026-10-25 02:30:00+00:00", "2026-10-25 00:30:00+00:00"),
    ],
)
def test_received_timestamp_normalization(analysis, host_timezone, stamp, utc_expected, vienna_expected):
    received = f"from source.example by destination.example with ESMTP; {stamp}"
    result = analysis.parseReceived(received, 1)
    expected = utc_expected if host_timezone == "UTC" else vienna_expected
    assert result["timestamp"] == expected
    assert result["host"] == "source.example"


def test_received_invalid_timestamp_remains_an_error(analysis, host_timezone):
    with pytest.raises(ValueError):
        analysis.parseReceived("from source.example by destination.example; invalid-timestamp", 1)


def test_received_missing_timestamp_stays_empty(analysis, host_timezone):
    result = analysis.parseReceived("from source.example by destination.example", 1)
    assert result["timestamp"] == ""
