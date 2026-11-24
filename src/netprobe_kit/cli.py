"""CLI for netprobe-kit."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from netprobe_kit.analyzer import DnsObservation, HttpObservation, TlsObservation, build_evidence_bundle


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netprobe-kit",
        description="Offline-reproducible DNS tampering, blockpage & TLS middlebox evidence analyzer.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="Analyze a synthetic ISP DNS sinkhole + TLS SNI reset incident")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        bundle = build_evidence_bundle(
            "probe-east-africa-001",
            dns=[
                DnsObservation(
                    domain="news.example.org",
                    local_ips=("127.0.0.1",),
                    control_ips=("93.184.216.34",),
                )
            ],
            http=[
                HttpObservation(
                    url="http://news.example.org/",
                    status_code=451,
                    body_excerpt="Access Denied by ISP pursuant to regulatory order.",
                    headers={},
                )
            ],
            tls=[
                TlsObservation(
                    hostname="chat.example.org",
                    tcp_connected=True,
                    tls_handshake_ok=False,
                    error_code="ECONNRESET",
                )
            ],
        )
        print(
            json.dumps(
                {
                    "probe_id": bundle.probe_id,
                    "interference_detected": bundle.interference_detected,
                    "evidence_sha256": bundle.evidence_sha256,
                    "findings": [
                        {
                            "classification": f.classification.value,
                            "target": f.target,
                            "confidence": f.confidence,
                            "detail": f.detail,
                        }
                        for f in bundle.findings
                    ],
                },
                indent=2,
            )
        )
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
