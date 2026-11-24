"""Tests for netprobe-kit DNS sinkhole/NXDOMAIN, HTTP blockpage/captive portal, TLS SNI & CLI."""

from __future__ import annotations

import json

import pytest

from netprobe_kit import (
    DnsObservation,
    HttpObservation,
    InterferenceClass,
    TlsObservation,
    build_evidence_bundle,
)
from netprobe_kit.cli import main as cli_main


def test_clean_network_observations_produce_zero_findings() -> None:
    bundle = build_evidence_bundle(
        "clean-1",
        dns=[DnsObservation("example.org", ("93.184.216.34",), ("93.184.216.34",))],
        http=[HttpObservation("http://example.org", 200, "<html>Welcome</html>", {})],
        tls=[TlsObservation("example.org", True, True, cert_cn_or_san=("*.example.org", "example.org"))],
    )
    assert bundle.interference_detected is False
    assert bundle.findings == ()
    assert len(bundle.evidence_sha256) == 64


def test_detects_dns_sinkhole_false_nxdomain_captive_portal_and_tls_middlebox() -> None:
    bundle = build_evidence_bundle(
        "tamper-1",
        dns=[
            DnsObservation("site1.org", ("10.0.0.1",), ("104.21.10.2",)),
            DnsObservation("site2.org", (), ("104.21.10.3",), local_rcode="NXDOMAIN", control_rcode="NOERROR"),
        ],
        http=[
            HttpObservation(
                "http://portal.test",
                302,
                "WiFi Login captive portal",
                {"location": "http://192.168.1.1/portal"},
            ),
        ],
        tls=[
            TlsObservation("blocked.org", True, False, error_code="ECONNRESET"),
            TlsObservation("mitm.org", True, True, cert_cn_or_san=("proxy.isp.local",)),
        ],
    )
    assert bundle.interference_detected is True
    classes = {f.classification for f in bundle.findings}
    assert classes == {
        InterferenceClass.DNS_BOGON_SINKHOLE,
        InterferenceClass.DNS_FALSE_NXDOMAIN,
        InterferenceClass.HTTP_CAPTIVE_PORTAL,
        InterferenceClass.TLS_SNI_RESET,
        InterferenceClass.TLS_MITM_CERT_MISMATCH,
    }


def test_cli_demo(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli_main(["demo"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["interference_detected"] is True
    assert len(out["findings"]) == 3
