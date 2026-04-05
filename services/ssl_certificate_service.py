import asyncio
from datetime import datetime
import json
import logging
import socket
import ssl
from typing import Optional

import httpx

from models import SslCertificateAnalysis, TrustStatus

logger = logging.getLogger(__name__)


class SslCertificateService:

    CRT_SH_URL = "https://crt.sh"

    @staticmethod
    async def analyze(domain: str) -> SslCertificateAnalysis:
        """
        Inspect certificate transparency data first, then fall back to a direct
        TLS handshake so third-party outages do not become false "no HTTPS"
        verdicts.
        """
        analysis = SslCertificateAnalysis(
            domain=domain,
            status=TrustStatus.UNKNOWN,
            risk_score=0,
            has_ssl=False,
        )

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{SslCertificateService.CRT_SH_URL}/",
                    params={"q": domain, "output": "json"},
                )

            if response.status_code == 200:
                certs = response.json()
                if certs:
                    SslCertificateService._apply_ct_results(analysis, domain, certs)
                    return analysis

                analysis.flags.append("No certificate transparency records were found")
            else:
                logger.warning("crt.sh lookup failed for %s with status %s", domain, response.status_code)
                analysis.flags.append("Certificate transparency service unavailable")

        except (httpx.HTTPError, json.JSONDecodeError) as exc:
            logger.error("Error querying crt.sh for %s: %s", domain, exc)
            analysis.flags.append("Certificate transparency lookup failed")
        except Exception as exc:
            logger.error("Unexpected error in SSL analysis for %s: %s", domain, exc)
            analysis.flags.append("Unexpected SSL analysis error")

        await SslCertificateService._apply_tls_fallback(analysis, domain)
        analysis.risk_score = min(analysis.risk_score, 15)
        return analysis

    @staticmethod
    def _apply_ct_results(
        analysis: SslCertificateAnalysis,
        domain: str,
        certs: list,
    ) -> None:
        latest_cert = sorted(
            certs,
            key=lambda item: item.get("not_before", ""),
            reverse=True,
        )[0]

        analysis.has_ssl = True
        analysis.ct_log_entries = len(certs)
        analysis.subject_alt_names = [
            name.strip()
            for name in str(latest_cert.get("name_value", "")).splitlines()
            if name.strip()
        ]

        issuer_name = latest_cert.get("issuer_name") or latest_cert.get("issuer_ca_id")
        if issuer_name:
            analysis.certificate_issuer = str(issuer_name)
            lowered_issuer = analysis.certificate_issuer.lower()
            if "let's encrypt" in lowered_issuer or "cloudflare" in lowered_issuer:
                analysis.is_free_ca = True

        issued_date = SslCertificateService._parse_cert_datetime(latest_cert.get("not_before"))
        expiry_date = SslCertificateService._parse_cert_datetime(latest_cert.get("not_after"))
        SslCertificateService._apply_certificate_dates(analysis, issued_date, expiry_date)

        if any(name.startswith("*.") for name in analysis.subject_alt_names):
            analysis.wildcard_cert = True

        if len(analysis.subject_alt_names) > 20:
            analysis.multiple_domains_on_cert = True
            analysis.risk_score += 7
            analysis.flags.append(
                f"Certificate covers {len(analysis.subject_alt_names)} domains (possible phishing farm indicator)"
            )
        elif len(analysis.subject_alt_names) > 5:
            analysis.risk_score += 2

        analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 5 else TrustStatus.VERIFIED
        analysis.risk_score = min(analysis.risk_score, 15)

    @staticmethod
    async def _apply_tls_fallback(analysis: SslCertificateAnalysis, domain: str) -> None:
        """
        Use a direct TLS connection to determine whether HTTPS works even when
        CT data is unavailable.
        """
        try:
            cert = await asyncio.to_thread(SslCertificateService._fetch_peer_certificate, domain)
        except Exception as exc:
            logger.warning("TLS handshake failed for %s: %s", domain, exc)
            analysis.flags.append("Direct TLS handshake failed")
            analysis.risk_score = min(15, max(analysis.risk_score, 6))
            analysis.status = TrustStatus.UNKNOWN
            return

        analysis.has_ssl = True
        analysis.flags.append("Used direct TLS handshake because certificate transparency data was unavailable")

        issued_date = SslCertificateService._parse_tls_datetime(cert.get("notBefore"))
        expiry_date = SslCertificateService._parse_tls_datetime(cert.get("notAfter"))
        SslCertificateService._apply_certificate_dates(analysis, issued_date, expiry_date)

        issuer = cert.get("issuer", ())
        issuer_parts = []
        for item in issuer:
            for key, value in item:
                if key == "commonName":
                    issuer_parts.append(value)
        if issuer_parts and not analysis.certificate_issuer:
            analysis.certificate_issuer = ", ".join(issuer_parts)

        san_entries = cert.get("subjectAltName", ())
        if san_entries:
            analysis.subject_alt_names = [value for _, value in san_entries]
            analysis.wildcard_cert = any(value.startswith("*.") for value in analysis.subject_alt_names)

        if analysis.status == TrustStatus.UNKNOWN:
            analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 5 else TrustStatus.VERIFIED

    @staticmethod
    def _fetch_peer_certificate(domain: str) -> dict:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                return secure_sock.getpeercert()

    @staticmethod
    def _apply_certificate_dates(
        analysis: SslCertificateAnalysis,
        issued_date: Optional[datetime],
        expiry_date: Optional[datetime],
    ) -> None:
        analysis.issued_date = issued_date
        analysis.expiry_date = expiry_date

        if issued_date:
            cert_age = datetime.now(issued_date.tzinfo) - issued_date
            analysis.cert_age_days = cert_age.days
            if analysis.cert_age_days < 30:
                analysis.cert_too_new = True
                analysis.risk_score += 8
                analysis.flags.append(f"Certificate issued only {analysis.cert_age_days} days ago")

        if expiry_date:
            expiry_delta = expiry_date - datetime.now(expiry_date.tzinfo)
            if expiry_delta.days < 30:
                analysis.cert_expiring_soon = True
                analysis.risk_score += 3
                analysis.flags.append("Certificate expiring soon (< 30 days)")

    @staticmethod
    def _parse_cert_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None

    @staticmethod
    def _parse_tls_datetime(value: Optional[str]) -> Optional[datetime]:
        if not value:
            return None
        try:
            timestamp = ssl.cert_time_to_seconds(value)
            return datetime.fromtimestamp(timestamp).astimezone()
        except Exception:
            return None
