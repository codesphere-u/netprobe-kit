"""netprobe-kit — Offline-reproducible DNS, HTTP & TLS network interference analyzer."""

from netprobe_kit.analyzer import (
    DnsObservation,
    HttpObservation,
    InterferenceClass,
    InterferenceFinding,
    NetworkEvidenceBundle,
    TlsObservation,
    analyze_dns,
    analyze_http,
    analyze_tls,
    build_evidence_bundle,
    is_bogon_or_sinkhole_ip,
)

__version__ = "0.1.0"

__all__ = [
    "DnsObservation",
    "HttpObservation",
    "InterferenceClass",
    "InterferenceFinding",
    "NetworkEvidenceBundle",
    "TlsObservation",
    "__version__",
    "analyze_dns",
    "analyze_http",
    "analyze_tls",
    "build_evidence_bundle",
    "is_bogon_or_sinkhole_ip",
]
