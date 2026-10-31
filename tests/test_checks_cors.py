"""CORS check: severity matrix, the anonymous Origin probe, and failure surfacing."""

import asyncio
import socket
from pathlib import Path
from typing import Dict, List, Optional

import httpx
import pytest

import aegisaudit.cli as cli_mod
import aegisaudit.runner as runner_mod
from aegisaudit.checks.cors import CORS_PROBE_ORIGIN, check_cors
from aegisaudit.config import AegisConfig, LimitsConfig
from aegisaudit.fetcher import Fetcher
from aegisaudit.models import ScanArtifact, Severity
from aegisaudit.scoring import resolve_category

CFG = AegisConfig()


def _artifact(headers: Optional[Dict[str, str]] = None, origin: Optional[str] = CORS_PROBE_ORIGIN):
    return ScanArtifact(
        url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        headers=headers or {},
        cookies={},
        body_snippet="",
        content_type="text/html",
        request_origin=origin,
    )


class TestSeverityMatrix:
    def test_reflected_origin_with_credentials_is_high(self):
        findings = check_cors(
            _artifact(
                {
                    "access-control-allow-origin": CORS_PROBE_ORIGIN,
                    "access-control-allow-credentials": "true",
                }
            ),
            CFG,
        )
        assert [(f.id, f.severity) for f in findings] == [
            ("cors-reflected-origin-credentials", Severity.HIGH)
        ]

    def test_reflected_origin_without_credentials_is_medium(self):
        findings = check_cors(_artifact({"access-control-allow-origin": CORS_PROBE_ORIGIN}), CFG)
        assert [(f.id, f.severity) for f in findings] == [
            ("cors-reflected-origin", Severity.MEDIUM)
        ]

    def test_reflected_origin_with_credentials_false_is_medium(self):
        findings = check_cors(
            _artifact(
                {
                    "access-control-allow-origin": CORS_PROBE_ORIGIN,
                    "access-control-allow-credentials": "false",
                }
            ),
            CFG,
        )
        assert [f.severity for f in findings] == [Severity.MEDIUM]

    def test_wildcard_without_credentials_is_info(self):
        findings = check_cors(_artifact({"access-control-allow-origin": "*"}), CFG)
        assert [(f.id, f.severity) for f in findings] == [("cors-wildcard", Severity.INFO)]

    def test_wildcard_with_credentials_is_low_and_says_browsers_reject_it(self):
        findings = check_cors(
            _artifact(
                {
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                }
            ),
            CFG,
        )
        assert [(f.id, f.severity) for f in findings] == [
            ("cors-wildcard-with-credentials", Severity.LOW)
        ]
        assert "reject" in findings[0].description.lower()
        assert "misconfiguration" in findings[0].description.lower()

    def test_no_cors_header_is_a_pass(self):
        # The scoring model has no "pass" finding: absence of a finding is the pass.
        assert check_cors(_artifact({"content-type": "text/html"}), CFG) == []

    def test_header_names_are_case_insensitive(self):
        findings = check_cors(
            _artifact(
                {
                    "Access-Control-Allow-Origin": CORS_PROBE_ORIGIN,
                    "Access-Control-Allow-Credentials": "true",
                }
            ),
            CFG,
        )
        assert [f.severity for f in findings] == [Severity.HIGH]

    def test_a_different_fixed_origin_is_not_reflection(self):
        findings = check_cors(
            _artifact({"access-control-allow-origin": "https://app.example.com"}), CFG
        )
        assert findings == []

    def test_artifact_that_was_not_an_origin_probe_is_ignored(self):
        # A plain page fetch carries no Origin, so its ACAO says nothing about reflection.
        art = _artifact({"access-control-allow-origin": "*"}, origin=None)
        assert check_cors(art, CFG) == []

    def test_findings_are_scored_in_their_own_category(self):
        findings = check_cors(_artifact({"access-control-allow-origin": CORS_PROBE_ORIGIN}), CFG)
        assert resolve_category(findings[0]) == "cors"


@pytest.fixture(autouse=True)
def mock_dns(monkeypatch):
    def resolve(host, port, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", port))
        ]

    monkeypatch.setattr("aegisaudit.ssrf.socket.getaddrinfo", resolve)


def _fetcher(handler) -> Fetcher:
    cfg = AegisConfig()
    cfg.limits = LimitsConfig(rate_per_sec=100)
    fetcher = Fetcher(cfg)
    fetcher.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return fetcher


class TestProbeRequest:
    def test_sends_origin_and_records_it_on_the_artifact(self):
        seen: List[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok")

        async def run():
            fetcher = _fetcher(handler)
            try:
                return await fetcher.fetch("https://example.com/", origin=CORS_PROBE_ORIGIN)
            finally:
                await fetcher.close()

        artifact = asyncio.run(run())
        assert artifact is not None
        assert artifact.request_origin == CORS_PROBE_ORIGIN
        assert seen[0].method == "GET"
        assert seen[0].headers["origin"] == CORS_PROBE_ORIGIN

    def test_plain_fetch_sends_no_origin(self):
        seen: List[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok")

        async def run():
            fetcher = _fetcher(handler)
            try:
                return await fetcher.fetch("https://example.com/")
            finally:
                await fetcher.close()

        artifact = asyncio.run(run())
        assert artifact is not None and artifact.request_origin is None
        assert "origin" not in seen[0].headers

    def test_probe_sends_no_credentials_even_with_a_cookie_in_the_jar(self):
        seen: List[httpx.Request] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request)
            return httpx.Response(200, text="ok", headers={"set-cookie": "sid=secret; Path=/"})

        async def run():
            fetcher = _fetcher(handler)
            try:
                await fetcher.fetch("https://example.com/")  # puts sid in the client jar
                jar_has_cookie = fetcher.client.cookies.get("sid") == "secret"
                await fetcher.fetch("https://example.com/", origin=CORS_PROBE_ORIGIN)
                return jar_has_cookie
            finally:
                await fetcher.close()

        assert asyncio.run(run()) is True  # precondition: the jar really holds a cookie
        probe = seen[1]
        assert "cookie" not in probe.headers
        assert "authorization" not in probe.headers

    def test_probe_does_not_follow_redirects(self):
        seen: List[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "https://example.com/account"})
            return httpx.Response(200, text="private")

        async def run():
            fetcher = _fetcher(handler)
            try:
                return await fetcher.fetch("https://example.com/", origin=CORS_PROBE_ORIGIN)
            finally:
                await fetcher.close()

        artifact = asyncio.run(run())
        assert seen == ["https://example.com/"]
        assert artifact is not None and artifact.status_code == 302

    def test_probe_is_still_ssrf_guarded(self, monkeypatch):
        def handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover
            raise AssertionError("request must not be sent")

        async def run():
            fetcher = _fetcher(handler)
            try:
                return await fetcher.fetch("http://169.254.169.254/", origin=CORS_PROBE_ORIGIN)
            finally:
                await fetcher.close()

        assert asyncio.run(run()) is None


class TestProbeCors:
    def test_failed_probe_is_reported_not_dropped(self):
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/down":
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="ok")

        async def run():
            fetcher = _fetcher(handler)
            try:
                return await fetcher.probe_cors(
                    ["https://example.com/up", "https://example.com/down"], CORS_PROBE_ORIGIN
                )
            finally:
                await fetcher.close()

        artifacts, failed = asyncio.run(run())
        assert [a.url for a in artifacts] == ["https://example.com/up"]
        assert failed == ["https://example.com/down (CORS probe)"]


class TestRunnerRouting:
    def test_probe_artifacts_only_run_probe_checks(self, monkeypatch):
        calls: List[str] = []
        monkeypatch.setattr(
            runner_mod,
            "CHECK_MODULES",
            [lambda art, cfg: calls.append(f"page:{art.request_origin}") or []],
        )
        monkeypatch.setattr(
            runner_mod,
            "PROBE_CHECK_MODULES",
            [lambda art, cfg: calls.append(f"probe:{art.request_origin}") or []],
        )
        page = _artifact(origin=None)
        probe = _artifact(origin=CORS_PROBE_ORIGIN)
        result = runner_mod.Runner(CFG).run_checks([page, probe])
        assert sorted(calls) == ["page:None", f"probe:{CORS_PROBE_ORIGIN}"]
        assert result.targets == ["https://example.com/"]

    def test_real_registration_includes_cors_as_a_probe_check(self):
        assert check_cors in runner_mod.PROBE_CHECK_MODULES
        assert check_cors not in runner_mod.CHECK_MODULES


class TestRunScanEndToEnd:
    def test_reflection_is_reported_and_a_failed_probe_surfaces_as_failed_target(
        self, monkeypatch, tmp_path: Path
    ):
        def handler(request: httpx.Request) -> httpx.Response:
            origin = request.headers.get("origin")
            if origin and request.url.path == "/down":
                raise httpx.ConnectError("boom")
            headers = {}
            if origin:
                headers = {
                    "access-control-allow-origin": origin,
                    "access-control-allow-credentials": "true",
                }
            return httpx.Response(200, text="ok", headers=headers)

        monkeypatch.setattr(cli_mod, "Fetcher", lambda cfg: _fetcher(handler))
        monkeypatch.setattr(runner_mod, "CHECK_MODULES", [])

        urls = ["https://example.com/", "https://example.com/down"]
        result = asyncio.run(
            cli_mod.run_scan(
                urls,
                CFG,
                output_dir=tmp_path,
                formats={"json"},
                save_history=False,
                cors_targets=urls,
            )
        )
        assert result is not None
        assert [f.id for f in result.findings] == ["cors-reflected-origin-credentials"]
        assert result.findings[0].severity == Severity.HIGH
        # The plain page fetch of /down succeeded; only its CORS probe failed.
        assert result.failed_targets == ["https://example.com/down (CORS probe)"]
