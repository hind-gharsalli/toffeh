import asyncio
import logging
import time
from datetime import datetime
from urllib.parse import urlparse

from models import (
    RiskLevel,
    SourceCredibilityRequest,
    SourceCredibilityResponse,
    TrustStatus,
)
from services.dns_history_service import DnsHistoryService
from services.ip_geolocation_service import IpGeolocationService
from services.security_headers_service import SecurityHeadersService
from services.ssl_certificate_service import SslCertificateService
from services.stylometric_service import StylometricService
from services.user_reputation_service import UserReputationService
from services.whois_service import WhoisService

logger = logging.getLogger(__name__)


class SourceCredibilityOrchestrator:

    @staticmethod
    async def analyze(request: SourceCredibilityRequest) -> SourceCredibilityResponse:
        """
        Master function: orchestrate all analyses and convert partial component
        results into an honest final verdict.
        """
        start_time = time.time()

        domain = request.domain
        if not domain and request.url:
            domain = urlparse(str(request.url)).netloc.lower()
            if ":" in domain:
                domain = domain.split(":", 1)[0]
            if domain.startswith("www."):
                domain = domain[4:]

        if not domain:
            raise ValueError("Either URL or domain must be provided")

        logger.info(f"Starting source credibility analysis for: {domain}")

        try:
            (
                whois_analysis,
                dns_analysis,
                ssl_analysis,
                ip_analysis,
                headers_analysis,
            ) = await asyncio.gather(
                WhoisService.analyze(domain),
                DnsHistoryService.analyze(domain),
                SslCertificateService.analyze(domain),
                IpGeolocationService.analyze(domain, claimed_origin=None),
                SecurityHeadersService.analyze(domain),
                return_exceptions=False,
            )

            user_analysis = None
            if request.username or request.source_account:
                username = request.username or request.source_account
                user_analysis = await UserReputationService.analyze(username)

            stylometric_analysis = None
            if request.current_text or request.historical_texts:
                stylometric_analysis = await StylometricService.analyze(
                    current_text=request.current_text or "",
                    historical_texts=request.historical_texts,
                )

        except Exception as exc:
            logger.error(f"Error during parallel analysis: {exc}")
            raise

        component_analyses = [
            whois_analysis,
            dns_analysis,
            ssl_analysis,
            ip_analysis,
            headers_analysis,
        ]
        if user_analysis:
            component_analyses.append(user_analysis)
        if stylometric_analysis:
            component_analyses.append(stylometric_analysis)

        raw_risk_score = sum(analysis.risk_score for analysis in component_analyses)
        unknown_components = [
            analysis for analysis in component_analyses
            if analysis.status == TrustStatus.UNKNOWN
        ]
        suspicious_components = [
            analysis for analysis in component_analyses
            if analysis.status == TrustStatus.SUSPICIOUS
        ]
        high_risk_components = [
            analysis for analysis in component_analyses
            if analysis.status == TrustStatus.HIGH_RISK
        ]

        # Unknown components should reduce trust because lack of evidence is not
        # evidence of safety.
        coverage_penalty = len(unknown_components) * 8
        adjusted_risk_score = min(100, raw_risk_score + coverage_penalty)
        trust_score = max(0, 100 - adjusted_risk_score)

        if adjusted_risk_score >= 75:
            risk_level = RiskLevel.CRITICAL
            trust_status = TrustStatus.HIGH_RISK
        elif adjusted_risk_score >= 50:
            risk_level = RiskLevel.HIGH
            trust_status = TrustStatus.HIGH_RISK
        elif adjusted_risk_score >= 25:
            risk_level = RiskLevel.MEDIUM
            trust_status = TrustStatus.SUSPICIOUS
        else:
            risk_level = RiskLevel.LOW
            trust_status = TrustStatus.VERIFIED

        if trust_status == TrustStatus.VERIFIED and unknown_components:
            trust_status = TrustStatus.UNKNOWN

        if (
            unknown_components and
            len(unknown_components) >= max(2, len(component_analyses) // 2) and
            not suspicious_components and
            not high_risk_components
        ):
            trust_status = TrustStatus.UNKNOWN
            risk_level = RiskLevel.MEDIUM

        if trust_status == TrustStatus.VERIFIED and suspicious_components:
            trust_status = TrustStatus.SUSPICIOUS
            risk_level = RiskLevel.MEDIUM

        if high_risk_components and risk_level in {RiskLevel.LOW, RiskLevel.MEDIUM}:
            risk_level = RiskLevel.HIGH
            trust_status = TrustStatus.HIGH_RISK

        all_flags = (
            whois_analysis.flags +
            dns_analysis.flags +
            ssl_analysis.flags +
            ip_analysis.flags +
            headers_analysis.flags +
            (user_analysis.flags if user_analysis else []) +
            (stylometric_analysis.flags if stylometric_analysis else [])
        )

        all_risks = [
            {"component": "WHOIS", "status": whois_analysis.status, "score": whois_analysis.risk_score, "flags": whois_analysis.flags},
            {"component": "DNS_History", "status": dns_analysis.status, "score": dns_analysis.risk_score, "flags": dns_analysis.flags},
            {"component": "SSL_Certificate", "status": ssl_analysis.status, "score": ssl_analysis.risk_score, "flags": ssl_analysis.flags},
            {"component": "IP_Geolocation", "status": ip_analysis.status, "score": ip_analysis.risk_score, "flags": ip_analysis.flags},
            {"component": "Security_Headers", "status": headers_analysis.status, "score": headers_analysis.risk_score, "flags": headers_analysis.flags},
        ]
        if user_analysis:
            all_risks.append({
                "component": "User_Reputation",
                "status": user_analysis.status,
                "score": user_analysis.risk_score,
                "flags": user_analysis.flags,
            })
        if stylometric_analysis:
            all_risks.append({
                "component": "Stylometry",
                "status": stylometric_analysis.status,
                "score": stylometric_analysis.risk_score,
                "flags": stylometric_analysis.flags,
            })

        confidence = SourceCredibilityOrchestrator._calculate_confidence(
            total_components=len(component_analyses),
            unknown_components=len(unknown_components),
            risk_level=risk_level,
        )

        summary = SourceCredibilityOrchestrator._generate_summary(
            domain=domain,
            risk_level=risk_level,
            trust_status=trust_status,
            all_flags=all_flags,
            unknown_count=len(unknown_components),
        )

        if trust_status == TrustStatus.UNKNOWN:
            recommendation = "RESEARCH"
        elif risk_level in {RiskLevel.CRITICAL, RiskLevel.HIGH}:
            recommendation = "AVOID"
        elif risk_level == RiskLevel.MEDIUM:
            recommendation = "VERIFY"
        else:
            recommendation = "TRUSTED"

        duration_ms = (time.time() - start_time) * 1000

        response = SourceCredibilityResponse(
            domain=domain,
            url=str(request.url) if request.url else None,
            risk_level=risk_level,
            trust_status=trust_status,
            confidence=confidence,
            trust_score=trust_score,
            raw_risk_score=adjusted_risk_score,
            whois_analysis=whois_analysis,
            dns_history_analysis=dns_analysis,
            ssl_analysis=ssl_analysis,
            ip_geolocation_analysis=ip_analysis,
            security_headers_analysis=headers_analysis,
            user_reputation_analysis=user_analysis,
            stylometric_analysis=stylometric_analysis,
            all_flags=all_flags,
            all_risks=all_risks,
            summary=summary,
            recommendation=recommendation,
            analysis_timestamp=datetime.now(),
            analysis_duration_ms=duration_ms,
        )

        logger.info(
            "Analysis complete for %s: trust_score=%s, confidence=%s, trust_status=%s",
            domain,
            trust_score,
            confidence,
            trust_status,
        )

        return response

    @staticmethod
    def _generate_summary(
        domain: str,
        risk_level: RiskLevel,
        trust_status: TrustStatus,
        all_flags: list,
        unknown_count: int,
    ) -> str:
        if trust_status == TrustStatus.UNKNOWN:
            return (
                f"INCONCLUSIVE: Domain '{domain}' did not trigger major risk signals, "
                f"but {unknown_count} analysis component(s) could not be verified. "
                f"More research is recommended before trusting it."
            )

        if risk_level == RiskLevel.CRITICAL:
            return (
                f"CRITICAL: Domain '{domain}' poses a severe threat. "
                f"Do not interact with this site. "
                f"{len(all_flags)} risk indicators detected."
            )

        if risk_level == RiskLevel.HIGH:
            top_flags = "; ".join(all_flags[:3]) or "multiple severe risk indicators"
            return (
                f"HIGH RISK: Domain '{domain}' shows multiple suspicious indicators. "
                f"Key concerns: {top_flags}. "
                f"Verify independently before trusting content from this source."
            )

        if risk_level == RiskLevel.MEDIUM:
            return (
                f"SUSPICIOUS: Domain '{domain}' has concerning characteristics. "
                f"{len(all_flags)} issue(s) were detected. "
                f"Independent verification is recommended."
            )

        return (
            f"VERIFIED: Domain '{domain}' appears legitimate. "
            f"No major red flags were detected across the completed analyses."
        )

    @staticmethod
    def _calculate_confidence(
        total_components: int,
        unknown_components: int,
        risk_level: RiskLevel,
    ) -> float:
        base_confidence = {
            RiskLevel.LOW: 0.82,
            RiskLevel.MEDIUM: 0.78,
            RiskLevel.HIGH: 0.86,
            RiskLevel.CRITICAL: 0.90,
        }[risk_level]

        confidence = base_confidence - (unknown_components * 0.12)
        if total_components > 5:
            confidence += 0.03

        return max(0.20, min(0.95, round(confidence, 2)))
