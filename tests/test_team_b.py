import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from main import app
from models import (
    DnsHistoryAnalysis,
    IpGeolocationAnalysis,
    SecurityHeadersAnalysis,
    SourceCredibilityRequest,
    SslCertificateAnalysis,
    StylometricAnalysis,
    TrustStatus,
    WhoisAnalysis,
)
from services.dns_history_service import DnsHistoryService
from services.ip_geolocation_service import IpGeolocationService
from services.orchestrator import SourceCredibilityOrchestrator
from services.security_headers_service import SecurityHeadersService
from services.ssl_certificate_service import SslCertificateService
from services.stylometric_service import StylometricService
from services.whois_service import WhoisService

# ============================================================================
# FIXTURES
# ============================================================================

@pytest_asyncio.fixture
async def client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac

# ============================================================================
# BASIC TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_health_check(client):
    """Test health endpoint"""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

@pytest.mark.asyncio
async def test_root_endpoint(client):
    """Test root endpoint"""
    response = await client.get("/")
    assert response.status_code == 200
    assert "service" in response.json()

@pytest.mark.asyncio
async def test_scoring_docs(client):
    """Test scoring documentation endpoint"""
    response = await client.get("/api/docs/scoring")
    assert response.status_code == 200
    data = response.json()
    assert "trust_score_breakdown" in data
    assert "scoring_components" in data

# ============================================================================
# ANALYSIS TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_analyze_trusted_domain(client):
    """Test analysis of a known trusted domain"""
    request = SourceCredibilityRequest(
        domain="bbc.com"
    )
    
    response = await client.post(
        "/api/analyze-source",
        json=request.dict()
    )
    
    assert response.status_code == 200
    data = response.json()
    
    # BBC should be trusted
    assert data["trust_score"] >= 60
    assert data["risk_level"] in ["LOW", "MEDIUM"]
    assert data["recommendation"] in ["TRUSTED", "VERIFY", "RESEARCH"]

@pytest.mark.asyncio
async def test_analyze_suspicious_domain(client):
    """Test analysis of a suspicious domain"""
    request = SourceCredibilityRequest(
        domain="reuter-news.com"
    )
    
    response = await client.post(
        "/api/analyze-source",
        json=request.dict()
    )
    
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_analyze_with_url(client):
    """Test analysis with full URL"""
    request = SourceCredibilityRequest(
        url="https://example.com/article"
    )
    
    response = await client.post(
        "/api/analyze-source",
        json=request.dict()
    )
    
    assert response.status_code == 200
    assert "example.com" in response.json()["domain"]

@pytest.mark.asyncio
async def test_missing_input(client):
    """Test error handling for missing input"""
    request = SourceCredibilityRequest()
    
    response = await client.post(
        "/api/analyze-source",
        json=request.dict()
    )
    
    assert response.status_code == 400

# ============================================================================
# COMPONENT TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_whois_analysis():
    """Test WHOIS analysis independently"""
    from services.whois_service import WhoisService
    
    result = await WhoisService.analyze("github.com")
    
    assert result.domain == "github.com"
    assert result.registered_date is not None
    assert result.domain_age_days >= 0
    assert 0 <= result.risk_score <= 20

@pytest.mark.asyncio
async def test_dns_history_analysis():
    """Test DNS history analysis"""
    from services.dns_history_service import DnsHistoryService
    
    result = await DnsHistoryService.analyze("google.com")
    
    assert result.domain == "google.com"
    assert len(result.historical_ips) > 0
    assert 0 <= result.risk_score <= 15

@pytest.mark.asyncio
async def test_ssl_analysis():
    """Test SSL certificate analysis"""
    from services.ssl_certificate_service import SslCertificateService
    
    result = await SslCertificateService.analyze("google.com")
    
    assert result.domain == "google.com"
    assert result.has_ssl == True
    assert 0 <= result.risk_score <= 15

@pytest.mark.asyncio
async def test_ip_geolocation_analysis():
    """Test IP geolocation analysis"""
    from services.ip_geolocation_service import IpGeolocationService
    
    result = await IpGeolocationService.analyze("google.com")
    
    assert result.ip_address != "unknown"
    assert result.country is not None
    assert 0 <= result.risk_score <= 10



@pytest.mark.asyncio
async def test_security_headers_analysis():
    """Test HTTP security headers analysis"""
    from services.security_headers_service import SecurityHeadersService
    
    result = await SecurityHeadersService.analyze("google.com")
    
    assert result.domain == "google.com"
    assert result.headers_grade is not None
    assert 0 <= result.risk_score <= 10

# ============================================================================
# BATCH TESTS
# ============================================================================

@pytest.mark.asyncio
async def test_batch_analysis(client):
    """Test batch analysis"""
    requests_list = [
        SourceCredibilityRequest(domain="google.com"),
        SourceCredibilityRequest(domain="facebook.com"),
        SourceCredibilityRequest(domain="unknown-fake-site.xyz")
    ]
    
    response = await client.post(
        "/api/batch-analyze",
        json=[r.dict() for r in requests_list]
    )
    
    assert response.status_code == 200
    data = response.json()
    assert len(data["results"]) == 3

# ============================================================================
# EDGE CASES
# ============================================================================

@pytest.mark.asyncio
async def test_invalid_domain(client):
    """Test handling of invalid domain"""
    response = await client.post(
        "/api/analyze-source",
        json={"domain": "not a valid domain !!! @@@@"}
    )
    
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_domain_with_www(client):
    """Test domain with www prefix (should be cleaned)"""
    request = SourceCredibilityRequest(
        domain="www.example.com"
    )
    
    response = await client.post(
        "/api/analyze-source",
        json=request.dict()
    )
    
    assert response.status_code == 200
    assert "www" not in response.json()["domain"]

@pytest.mark.asyncio
async def test_localhost_domain_rejected(client):
    response = await client.post(
        "/api/analyze-source",
        json={"domain": "localhost"}
    )

    assert response.status_code == 422

@pytest.mark.asyncio
async def test_url_domain_mismatch_rejected(client):
    response = await client.post(
        "/api/analyze-source",
        json={"url": "https://example.com/news", "domain": "bbc.com"}
    )

    assert response.status_code == 422

def test_domain_field_normalizes_url_like_input():
    request = SourceCredibilityRequest(domain="https://www.example.com/article")
    assert request.domain == "example.com"

@pytest.mark.asyncio
async def test_inconclusive_result_is_not_verified(monkeypatch):
    async def fake_whois(domain):
        return WhoisAnalysis(domain=domain, status=TrustStatus.UNKNOWN, risk_score=0, flags=["whois unavailable"])

    async def fake_dns(domain):
        return DnsHistoryAnalysis(domain=domain, status=TrustStatus.UNKNOWN, risk_score=0, flags=["dns unavailable"])

    async def fake_ssl(domain):
        return SslCertificateAnalysis(domain=domain, status=TrustStatus.UNKNOWN, risk_score=0, flags=["ssl unavailable"])

    async def fake_ip(domain, claimed_origin=None):
        return IpGeolocationAnalysis(ip_address="unknown", status=TrustStatus.UNKNOWN, risk_score=0, flags=["ip unavailable"])

    async def fake_headers(domain):
        return SecurityHeadersAnalysis(domain=domain, status=TrustStatus.UNKNOWN, risk_score=0, flags=["headers unavailable"])

    monkeypatch.setattr(WhoisService, "analyze", staticmethod(fake_whois))
    monkeypatch.setattr(DnsHistoryService, "analyze", staticmethod(fake_dns))
    monkeypatch.setattr(SslCertificateService, "analyze", staticmethod(fake_ssl))
    monkeypatch.setattr(IpGeolocationService, "analyze", staticmethod(fake_ip))
    monkeypatch.setattr(SecurityHeadersService, "analyze", staticmethod(fake_headers))

    result = await SourceCredibilityOrchestrator.analyze(SourceCredibilityRequest(domain="example.com"))

    assert result.trust_status == "UNKNOWN"
    assert result.recommendation == "RESEARCH"
    assert result.trust_score < 100
    assert "INCONCLUSIVE" in result.summary

@pytest.mark.asyncio
async def test_stylometric_service_detects_shift():
    historical = [
        "Public health reporting requires careful verification of each source. We cite peer reviewed studies and official datasets before publishing any claim.",
        "Our newsroom follows a careful health reporting workflow. We compare official studies, interview experts, and verify every statistic before publication.",
        "Each article in this health brief cites primary studies, public data, and specialist interviews. Accuracy matters more than speed."
    ]
    current = (
        "BREAKING!!! patriots rise NOW now now!!! The election machine is everywhere!!! "
        "Share this immediately!!! Nobody can wait, nobody can pause, nobody can verify anything. "
        "This is a total betrayal, a shocking fraud, a scandal hiding in plain sight, and everyone must forward this post tonight. "
        "Wake up, fight back, push this message, repeat it again and again before they erase the truth."
    )

    result = await StylometricService.analyze(current_text=current, historical_texts=historical)

    assert result.status in {TrustStatus.SUSPICIOUS, TrustStatus.HIGH_RISK}
    assert result.stylistic_shift_detected is True
    assert result.risk_score >= 4

@pytest.mark.asyncio
async def test_stylometric_analysis_is_included_when_texts_are_provided(monkeypatch):
    async def fake_whois(domain):
        return WhoisAnalysis(domain=domain, status=TrustStatus.VERIFIED, risk_score=0)

    async def fake_dns(domain):
        return DnsHistoryAnalysis(domain=domain, status=TrustStatus.VERIFIED, risk_score=0)

    async def fake_ssl(domain):
        return SslCertificateAnalysis(domain=domain, status=TrustStatus.VERIFIED, risk_score=0, has_ssl=True)

    async def fake_ip(domain, claimed_origin=None):
        return IpGeolocationAnalysis(ip_address="8.8.8.8", status=TrustStatus.VERIFIED, risk_score=0)

    async def fake_headers(domain):
        return SecurityHeadersAnalysis(domain=domain, status=TrustStatus.VERIFIED, risk_score=0, headers_grade="A")

    monkeypatch.setattr(WhoisService, "analyze", staticmethod(fake_whois))
    monkeypatch.setattr(DnsHistoryService, "analyze", staticmethod(fake_dns))
    monkeypatch.setattr(SslCertificateService, "analyze", staticmethod(fake_ssl))
    monkeypatch.setattr(IpGeolocationService, "analyze", staticmethod(fake_ip))
    monkeypatch.setattr(SecurityHeadersService, "analyze", staticmethod(fake_headers))

    request = SourceCredibilityRequest(
        domain="example.com",
        current_text="Markets moved sharply today. Traders reacted to earnings and central bank signals in a short burst of volatility.",
        historical_texts=[
            "Markets moved steadily this week as traders reacted to earnings and economic releases.",
            "Central bank signals and earnings reports shaped market sentiment across the session."
        ],
    )

    result = await SourceCredibilityOrchestrator.analyze(request)

    assert result.stylometric_analysis is not None
    assert any(risk["component"] == "Stylometry" for risk in result.all_risks)

# ============================================================================
# RUN TESTS
# ============================================================================

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
