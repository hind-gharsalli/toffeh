import ipaddress
from urllib.parse import urlparse

from pydantic import BaseModel, Field, HttpUrl, root_validator, validator
from typing import List, Dict, Optional, Literal
from datetime import datetime
from enum import Enum
import validators

# ============================================================================
# ENUMS
# ============================================================================

class RiskLevel(str, Enum):
    """Risk level classification"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class TrustStatus(str, Enum):
    """Overall trust status"""
    VERIFIED = "VERIFIED"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH_RISK = "HIGH_RISK"
    UNKNOWN = "UNKNOWN"

# ============================================================================
# INPUT MODELS
# ============================================================================

class SourceCredibilityRequest(BaseModel):
    """What Team B receives as input"""
    
    url: Optional[HttpUrl] = Field(None, description="Full URL to analyze")
    domain: Optional[str] = Field(None, description="Domain name (auto-extracted if URL provided)")
    source_account: Optional[str] = Field(None, description="Social media handle for bonus analysis")
    username: Optional[str] = Field(None, description="Username to search (for Sherlock)")
    current_text: Optional[str] = Field(None, description="Current article/post text for optional stylometric analysis")
    historical_texts: List[str] = Field(default_factory=list, description="Historical texts from the same source for optional stylometric analysis")

    @validator("domain")
    def normalize_domain(cls, value: Optional[str]) -> Optional[str]:
        if value is None:
            return None

        candidate = value.strip().lower()
        if not candidate:
            return None

        if "://" in candidate:
            parsed = urlparse(candidate)
            candidate = parsed.netloc or parsed.path

        if "/" in candidate:
            candidate = candidate.split("/", 1)[0]

        if "@" in candidate:
            raise ValueError("Domain must not contain user information")

        if ":" in candidate:
            host, _, maybe_port = candidate.partition(":")
            if maybe_port.isdigit():
                candidate = host

        candidate = candidate.rstrip(".")
        if candidate.startswith("www."):
            candidate = candidate[4:]

        cls._validate_public_host(candidate)
        return candidate

    @root_validator
    def validate_request_inputs(cls, values: Dict) -> Dict:
        url = values.get("url")
        domain = values.get("domain")

        if not url and not domain:
            return values

        if url:
            url_host = urlparse(str(url)).netloc.lower()
            if ":" in url_host:
                url_host = url_host.split(":", 1)[0]
            if url_host.startswith("www."):
                url_host = url_host[4:]

            cls._validate_public_host(url_host)

            if domain and domain != url_host:
                raise ValueError("Provided domain does not match the URL host")

            values["domain"] = domain or url_host

        return values

    @staticmethod
    def _validate_public_host(candidate: str) -> None:
        if candidate in {"localhost", "0.0.0.0"}:
            raise ValueError("Local or internal hosts are not allowed")

        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            ip = None

        if ip is not None:
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                raise ValueError("Private or internal IP addresses are not allowed")
            raise ValueError("IP addresses are not accepted; provide a public domain name")

        if not validators.domain(candidate):
            raise ValueError("Invalid domain format")
    
    class Config:
        example = {
            "url": "https://example-news.com/article",
            "domain": "example-news.com",
            "source_account": "@example_user"
        }

# ============================================================================
# SUB-SCORE MODELS (Individual analysis components)
# ============================================================================

class WhoisAnalysis(BaseModel):
    """WHOIS & domain registration analysis"""
    
    domain: str
    status: TrustStatus
    risk_score: int = Field(0, ge=0, le=20, description="0-20 points")
    
    details: Dict = Field(default_factory=dict)
    flags: List[str] = Field(default_factory=list)
    
    # Specific findings
    domain_age_days: Optional[int] = None
    registered_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    registrar: Optional[str] = None
    registrant_country: Optional[str] = None
    is_privacy_protected: bool = False
    is_recently_registered: bool = False  # < 90 days
    is_expiring_soon: bool = False  # < 60 days
    
    class Config:
        example = {
            "domain": "example.com",
            "status": "SUSPICIOUS",
            "risk_score": 15,
            "domain_age_days": 25,
            "is_recently_registered": True,
            "flags": ["Domain registered only 25 days ago", "Registrar: suspicious offshore provider"]
        }

class DnsHistoryAnalysis(BaseModel):
    """DNS & nameserver history"""
    
    domain: str
    status: TrustStatus
    risk_score: int = Field(0, ge=0, le=15, description="0-15 points")
    
    current_ips: List[str] = Field(default_factory=list)
    historical_ips: List[str] = Field(default_factory=list)
    recent_changes: int = 0
    flags: List[str] = Field(default_factory=list)
    
    has_suspicious_ip_change: bool = False
    nameservers: List[str] = Field(default_factory=list)
    nameserver_changes: int = 0
    
    class Config:
        example = {
            "domain": "example.com",
            "current_ips": ["192.168.1.1"],
            "recent_changes": 3,
            "flags": ["IP changed 3 times in 30 days"],
            "has_suspicious_ip_change": True
        }

class SslCertificateAnalysis(BaseModel):
    """SSL/TLS certificate analysis"""
    
    domain: str
    status: TrustStatus
    risk_score: int = Field(0, ge=0, le=15, description="0-15 points")
    
    has_ssl: bool = False
    certificate_issuer: Optional[str] = None
    issued_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    cert_age_days: Optional[int] = None
    is_self_signed: bool = False
    is_free_ca: bool = False  # Let's Encrypt, etc.
    
    # CT log analysis
    ct_log_entries: int = 0
    subject_alt_names: List[str] = Field(default_factory=list)
    
    # Risk indicators
    cert_too_new: bool = False  # < 30 days
    cert_expiring_soon: bool = False  # < 30 days
    wildcard_cert: bool = False
    multiple_domains_on_cert: bool = False
    
    flags: List[str] = Field(default_factory=list)
    
    class Config:
        example = {
            "domain": "example.com",
            "has_ssl": True,
            "certificate_issuer": "Let's Encrypt",
            "is_free_ca": True,
            "cert_age_days": 3,
            "cert_too_new": True,
            "flags": ["Certificate issued only 3 days ago"]
        }

class IpGeolocationAnalysis(BaseModel):
    """IP geolocation vs claimed origin"""
    
    ip_address: str
    status: TrustStatus
    risk_score: int = Field(0, ge=0, le=10, description="0-10 points")
    
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    org: Optional[str] = None
    
    # Risk indicators
    is_vpn_proxy: bool = False
    is_tor_exit: bool = False
    is_bulletproof_hoster: bool = False
    is_datacenter: bool = False
    abuse_reports: int = 0
    
    # Comparison
    claimed_origin: Optional[str] = None  # What domain claims
    matches_claimed_origin: bool = True
    
    flags: List[str] = Field(default_factory=list)
    
    class Config:
        example = {
            "ip_address": "192.168.1.1",
            "country": "RU",
            "is_vpn_proxy": False,
            "abuse_reports": 5,
            "flags": ["Server in Russia, claimed to be in UK"]
        }



class SecurityHeadersAnalysis(BaseModel):
    """HTTP security headers check"""
    
    domain: str
    status: TrustStatus
    risk_score: int = Field(0, ge=0, le=10, description="0-10 points")
    
    headers_grade: Optional[str] = None  # A+, A, B, C, D, E, F
    security_headers_present: List[str] = Field(default_factory=list)
    security_headers_missing: List[str] = Field(default_factory=list)
    
    has_hsts: bool = False
    has_csp: bool = False
    has_x_frame_options: bool = False
    has_x_content_type_options: bool = False
    has_referrer_policy: bool = False
    
    flags: List[str] = Field(default_factory=list)
    
    class Config:
        example = {
            "domain": "example.com",
            "headers_grade": "F",
            "security_headers_missing": ["HSTS", "CSP", "X-Frame-Options"],
            "flags": ["No HSTS header (grade F)"]
        }

class UserReputationAnalysis(BaseModel):
    """Optional: Social media account analysis"""
    
    username: Optional[str] = None
    status: TrustStatus = TrustStatus.UNKNOWN
    risk_score: int = Field(0, ge=0, le=15, description="0-15 points")
    
    # Account behavior
    account_age_days: Optional[int] = None
    is_new_account: bool = False  # < 30 days
    
    platforms_found: Dict[str, str] = Field(default_factory=dict)  # {"twitter": "url", "facebook": "url"}
    
    # Writing style consistency (if using LLM)
    writing_style_consistent: bool = True
    
    flags: List[str] = Field(default_factory=list)
    
    class Config:
        example = {
            "username": "example_user",
            "platforms_found": {"twitter": "https://twitter.com/example_user"},
            "is_new_account": True
        }

class StylometricAnalysis(BaseModel):
    """Optional: writing-style consistency analysis"""

    status: TrustStatus = TrustStatus.UNKNOWN
    risk_score: int = Field(0, ge=0, le=10, description="0-10 points")
    confidence: float = Field(0.0, ge=0.0, le=1.0)

    sample_count: int = 0
    current_word_count: int = 0
    baseline_word_count: int = 0
    style_distance: Optional[float] = None
    stylistic_shift_detected: bool = False

    details: Dict = Field(default_factory=dict)
    flags: List[str] = Field(default_factory=list)

    class Config:
        example = {
            "status": "SUSPICIOUS",
            "risk_score": 7,
            "confidence": 0.76,
            "sample_count": 4,
            "current_word_count": 420,
            "baseline_word_count": 1800,
            "style_distance": 0.41,
            "stylistic_shift_detected": True,
            "flags": ["Writing style differs significantly from historical samples"]
        }

# ============================================================================
# FINAL OUTPUT MODEL
# ============================================================================

class SourceCredibilityResponse(BaseModel):
    """Complete Team B output - what gets sent to Fusion Service"""
    
    # Request echo
    domain: str
    url: Optional[str] = None
    
    # Overall verdict
    risk_level: RiskLevel
    trust_status: TrustStatus
    confidence: float = Field(0.0, ge=0.0, le=1.0, description="0.0 to 1.0")
    
    # Main trust score (0-100)
    trust_score: int = Field(0, ge=0, le=100, description="Higher = more trustworthy")
    
    # Breakdown by component
    whois_analysis: WhoisAnalysis
    dns_history_analysis: DnsHistoryAnalysis
    ssl_analysis: SslCertificateAnalysis
    ip_geolocation_analysis: IpGeolocationAnalysis
    security_headers_analysis: SecurityHeadersAnalysis
    user_reputation_analysis: Optional[UserReputationAnalysis] = None
    stylometric_analysis: Optional[StylometricAnalysis] = None
    
    # Raw scores (sum of sub-scores)
    raw_risk_score: int = Field(0, ge=0, le=100, description="Sum of all risk points")
    
    # Consolidated findings
    all_flags: List[str] = Field(default_factory=list, description="All red flags combined")
    all_risks: List[Dict] = Field(default_factory=list, description="Detailed risk breakdown")
    
    # Human-readable explanation
    summary: str
    recommendation: Literal["TRUSTED", "VERIFY", "AVOID", "RESEARCH"] = "VERIFY"
    
    # Metadata
    analysis_timestamp: datetime
    analysis_duration_ms: float
    
    class Config:
        example = {
            "domain": "example-news.com",
            "risk_level": "HIGH",
            "trust_status": "HIGH_RISK",
            "confidence": 0.92,
            "trust_score": 25,
            "all_flags": [
                "Domain registered 15 days ago",
                "Server in Russia, claimed UK"
            ],
            "summary": "Multiple risk indicators suggest this domain impersonates Reuters.",
            "recommendation": "AVOID",
            "analysis_timestamp": "2024-01-15T10:30:00Z"
        }
