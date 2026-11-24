"""Offline-reproducible DNS tampering, HTTP blockpage/captive-portal & TLS middlebox evidence analyzer."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

_BLOCKPAGE_RE = re.compile(
    r"(?i)(access\s+denied\s+by\s+(?:isp|regulator|court|authority)|"
    r"site\s+blocked|blocked\s+pursuant\s+to|content\s+filtered|unavailable\s+for\s+legal\s+reasons)"
)
_CAPTIVE_PORTAL_RE = re.compile(
    r"(?i)(captive\s+portal|wifi\s+login|accept\s+terms\s+to\s+connect|buy\s+data\s+bundle|hotspot\s+sign\s*in)"
)


class InterferenceClass(StrEnum):
    NONE = "none"
    DNS_BOGON_SINKHOLE = "dns_bogon_sinkhole"
    DNS_FALSE_NXDOMAIN = "dns_false_nxdomain"
    DNS_IP_DIVERGENCE = "dns_ip_divergence"
    HTTP_BLOCKPAGE_INJECTION = "http_blockpage_injection"
    HTTP_CAPTIVE_PORTAL = "http_captive_portal"
    TLS_SNI_RESET = "tls_sni_reset"
    TLS_MITM_CERT_MISMATCH = "tls_mitm_cert_mismatch"


@dataclass(frozen=True)
class DnsObservation:
    domain: str
    local_ips: tuple[str, ...]
    control_ips: tuple[str, ...]  # From DoH/DoT or out-of-band control vantage
    local_rcode: str = "NOERROR"  # NOERROR, NXDOMAIN, SERVFAIL, TIMEOUT
    control_rcode: str = "NOERROR"
    local_ttl: int = 300


@dataclass(frozen=True)
class HttpObservation:
    url: str
    status_code: int
    body_excerpt: str
    headers: dict[str, str]
    control_status_code: int = 200


@dataclass(frozen=True)
class TlsObservation:
    hostname: str
    tcp_connected: bool
    tls_handshake_ok: bool
    error_code: str = ""  # e.g. ECONNRESET, ETIMEDOUT, CERTIFICATE_VERIFY_FAILED
    cert_cn_or_san: tuple[str, ...] = ()
    control_tls_ok: bool = True


@dataclass(frozen=True)
class InterferenceFinding:
    classification: InterferenceClass
    target: str
    confidence: str  # high | medium
    detail: str


@dataclass(frozen=True)
class NetworkEvidenceBundle:
    probe_id: str
    generated_at: str
    interference_detected: bool
    findings: tuple[InterferenceFinding, ...]
    evidence_sha256: str


def is_bogon_or_sinkhole_ip(raw_ip: str) -> bool:
    """Return True if an IP falls in RFC1918 private, loopback, CGNAT, link-local, or 0.0.0.0 sinkholes."""
    try:
        ip = ipaddress.ip_address(raw_ip.strip())
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_reserved)


def analyze_dns(obs: DnsObservation) -> list[InterferenceFinding]:
    """Compare local resolver answer against control resolver for sinkhole/NXDOMAIN tampering."""
    findings: list[InterferenceFinding] = []
    if obs.local_rcode.upper() == "NXDOMAIN" and obs.control_rcode.upper() == "NOERROR" and obs.control_ips:
        findings.append(
            InterferenceFinding(
                classification=InterferenceClass.DNS_FALSE_NXDOMAIN,
                target=obs.domain,
                confidence="high",
                detail=(
                    f"Local resolver returned NXDOMAIN for {obs.domain} while control resolved "
                    f"{list(obs.control_ips)}."
                ),
            )
        )
        return findings

    bogon_hits = [ip for ip in obs.local_ips if is_bogon_or_sinkhole_ip(ip)]
    if bogon_hits and obs.control_ips and not any(is_bogon_or_sinkhole_ip(ip) for ip in obs.control_ips):
        findings.append(
            InterferenceFinding(
                classification=InterferenceClass.DNS_BOGON_SINKHOLE,
                target=obs.domain,
                confidence="high",
                detail=f"Local resolver returned bogon/sinkhole IP(s) {bogon_hits} vs control {list(obs.control_ips)}.",
            )
        )
    elif obs.local_ips and obs.control_ips:
        local_prefixes = {".".join(ip.split(".")[:2]) for ip in obs.local_ips if "." in ip}
        ctrl_prefixes = {".".join(ip.split(".")[:2]) for ip in obs.control_ips if "." in ip}
        if local_prefixes and ctrl_prefixes and not (local_prefixes & ctrl_prefixes) and obs.local_ttl <= 5:
            findings.append(
                InterferenceFinding(
                    classification=InterferenceClass.DNS_IP_DIVERGENCE,
                    target=obs.domain,
                    confidence="medium",
                    detail=(
                        f"Disjoint /16 IP answer {list(obs.local_ips)} (TTL={obs.local_ttl}s) "
                        f"compared to control {list(obs.control_ips)}."
                    ),
                )
            )
    return findings


def analyze_http(obs: HttpObservation) -> list[InterferenceFinding]:
    """Detect HTTP 451/blockpage middlebox injection and Wi-Fi captive-portal hijacking."""
    findings: list[InterferenceFinding] = []
    if obs.status_code == 451 or _BLOCKPAGE_RE.search(obs.body_excerpt):
        findings.append(
            InterferenceFinding(
                classification=InterferenceClass.HTTP_BLOCKPAGE_INJECTION,
                target=obs.url,
                confidence="high",
                detail=f"HTTP {obs.status_code} response matches ISP/regulatory blockpage signature.",
            )
        )
    elif _CAPTIVE_PORTAL_RE.search(obs.body_excerpt) or (
        obs.status_code in (301, 302, 307) and "portal" in obs.headers.get("location", "").lower()
    ):
        findings.append(
            InterferenceFinding(
                classification=InterferenceClass.HTTP_CAPTIVE_PORTAL,
                target=obs.url,
                confidence="high",
                detail=f"HTTP {obs.status_code} intercepted by local captive portal.",
            )
        )
    return findings


def analyze_tls(obs: TlsObservation) -> list[InterferenceFinding]:
    """Distinguish TCP-connected SNI DPI resets & MITM certificates from origin outages."""
    findings: list[InterferenceFinding] = []
    if not obs.control_tls_ok:
        return findings

    if obs.tcp_connected and not obs.tls_handshake_ok:
        err_u = obs.error_code.upper()
        if "RESET" in err_u or "EOF" in err_u or "TIMEOUT" in err_u:
            findings.append(
                InterferenceFinding(
                    classification=InterferenceClass.TLS_SNI_RESET,
                    target=obs.hostname,
                    confidence="high",
                    detail=(
                        f"TCP succeeded to {obs.hostname}:443 but TLS ClientHello failed with "
                        f"{obs.error_code} while control succeeded (SNI middlebox pattern)."
                    ),
                )
            )
        elif "CERT" in err_u:
            findings.append(
                InterferenceFinding(
                    classification=InterferenceClass.TLS_MITM_CERT_MISMATCH,
                    target=obs.hostname,
                    confidence="high",
                    detail=(
                        f"TLS certificate verification failed ({obs.error_code}) "
                        f"with SANs {list(obs.cert_cn_or_san)}."
                    ),
                )
            )
    elif obs.tls_handshake_ok and obs.cert_cn_or_san:
        host = obs.hostname.lower()
        matched = any(
            host == pat.lower() or (pat.startswith("*.") and host.endswith(pat[1:].lower()))
            for pat in obs.cert_cn_or_san
        )
        if not matched:
            findings.append(
                InterferenceFinding(
                    classification=InterferenceClass.TLS_MITM_CERT_MISMATCH,
                    target=obs.hostname,
                    confidence="high",
                    detail=f"Presented certificate SANs {list(obs.cert_cn_or_san)} do not match '{obs.hostname}'.",
                )
            )
    return findings


def build_evidence_bundle(
    probe_id: str,
    *,
    dns: list[DnsObservation] | None = None,
    http: list[HttpObservation] | None = None,
    tls: list[TlsObservation] | None = None,
) -> NetworkEvidenceBundle:
    """Evaluate all collected probe observations and return a SHA-256 signed evidence bundle."""
    findings: list[InterferenceFinding] = []
    for d in dns or []:
        findings.extend(analyze_dns(d))
    for h in http or []:
        findings.extend(analyze_http(h))
    for t in tls or []:
        findings.extend(analyze_tls(t))

    ts = datetime.now(UTC).isoformat()
    payload: dict[str, Any] = {
        "probe_id": probe_id,
        "generated_at": ts,
        "interference_detected": bool(findings),
        "findings": [
            {
                "classification": f.classification.value,
                "target": f.target,
                "confidence": f.confidence,
                "detail": f.detail,
            }
            for f in findings
        ],
    }
    digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return NetworkEvidenceBundle(
        probe_id=probe_id,
        generated_at=ts,
        interference_detected=bool(findings),
        findings=tuple(findings),
        evidence_sha256=digest,
    )
