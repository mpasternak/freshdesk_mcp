"""Guards around the bulk-fetch tools.

These tools act on ticket content, which arrives from whoever emailed the
helpdesk. Anything derived from a ticket body is therefore attacker-influenced
input, and the tests below pin down the boundaries that keep it from turning
into outbound requests to internal services or unbounded local work.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

from freshdesk_mcp.server import (
    _download_one,
    _fetch_all_conversations,
    _reject_non_public_url,
)


class TestUrlValidation:
    def test_rejects_loopback(self):
        assert _reject_non_public_url("http://127.0.0.1/admin") is not None
        assert _reject_non_public_url("http://[::1]/admin") is not None
        assert _reject_non_public_url("http://localhost/admin") is not None

    def test_rejects_cloud_metadata_endpoint(self):
        # The canonical SSRF target: EC2/GCP/Azure instance metadata.
        assert _reject_non_public_url("http://169.254.169.254/latest/meta-data/") is not None

    def test_rejects_private_ranges(self):
        for url in (
            "http://10.0.0.5/x.png",
            "http://192.168.1.1/x.png",
            "http://172.16.0.1/x.png",
        ):
            assert _reject_non_public_url(url) is not None, url

    def test_rejects_non_http_schemes(self):
        assert _reject_non_public_url("file:///etc/passwd") is not None
        assert _reject_non_public_url("ftp://example.com/x") is not None
        assert _reject_non_public_url("gopher://example.com/x") is not None

    def test_rejects_url_without_host(self):
        assert _reject_non_public_url("http:///nohost") is not None

    def test_allows_public_address(self):
        # Public IP literal, so the check does not depend on DNS being reachable.
        assert _reject_non_public_url("https://93.184.216.34/image.png") is None


class TestDownloadGuard:
    def test_refuses_private_url_without_issuing_request(self, tmp_path: Path):
        client = MagicMock()
        client.stream = MagicMock(side_effect=AssertionError("no request may be made"))

        async def run():
            return await _download_one(
                client,
                "http://169.254.169.254/latest/meta-data/",
                tmp_path / "out.bin",
                validate_public=True,
            )

        try:
            asyncio.run(run())
        except ValueError as exc:
            assert "169.254.169.254" in str(exc)
        else:
            raise AssertionError("expected the download to be refused")

        client.stream.assert_not_called()


def _page_response(items, next_page=None):
    response = MagicMock()
    response.json.return_value = items
    link = f'<https://x/api/v2/tickets/1/conversations?page={next_page}>; rel="next"' if next_page else ""
    response.headers = {"Link": link}
    return response


class TestConversationPaging:
    def test_stops_at_max_pages_and_reports_truncation(self, monkeypatch):
        calls = []

        async def fake_get(client, path, params=None):
            calls.append(params["page"])
            # Always advertise another page, so only the cap can end the loop.
            return _page_response([{"id": params["page"]}], next_page=params["page"] + 1)

        monkeypatch.setattr("freshdesk_mcp.server._fd_get", fake_get)

        conversations, truncated = asyncio.run(
            _fetch_all_conversations(AsyncMock(), ticket_id=1, max_pages=3)
        )

        assert calls == [1, 2, 3]
        assert len(conversations) == 3
        assert truncated is True

    def test_reports_no_truncation_when_pages_run_out(self, monkeypatch):
        async def fake_get(client, path, params=None):
            return _page_response([{"id": 1}], next_page=None)

        monkeypatch.setattr("freshdesk_mcp.server._fd_get", fake_get)

        conversations, truncated = asyncio.run(
            _fetch_all_conversations(AsyncMock(), ticket_id=1, max_pages=10)
        )

        assert len(conversations) == 1
        assert truncated is False
