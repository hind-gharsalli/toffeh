import httpx
import logging
from models import SecurityHeadersAnalysis, TrustStatus

logger = logging.getLogger(__name__)

class SecurityHeadersService:
    
    SECURITYHEADERS_API = "https://api.securityheaders.com"
    
    @staticmethod
    async def analyze(domain: str) -> SecurityHeadersAnalysis:
        """
        Check HTTP security headers using securityheaders.com API
        FREE API, no key needed
        """
        
        analysis = SecurityHeadersAnalysis(
            domain=domain,
            status=TrustStatus.UNKNOWN,
            risk_score=0
        )
        
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                # Call securityheaders.com API
                response = await client.get(
                    f"{SecurityHeadersService.SECURITYHEADERS_API}/scan",
                    params={"uri": f"https://{domain}", "followRedirects": "on"}
                )
                
                if response.status_code != 200:
                    logger.warning(f"Security headers scan failed for {domain}")
                    await SecurityHeadersService._populate_headers_fallback(client, analysis, domain)
                    return analysis
                
                data = response.json()
                
                # Get the grade
                analysis.headers_grade = data.get("grade", "UNKNOWN")
                
                # Grade to risk mapping
                grade_risk_map = {
                    "A+": 0,
                    "A": 1,
                    "B": 2,
                    "C": 3,
                    "D": 4,
                    "E": 6,
                    "F": 10
                }
                
                analysis.risk_score = grade_risk_map.get(analysis.headers_grade, 5)
                
                # Map grades to status
                if analysis.headers_grade in ["A+", "A", "B"]:
                    analysis.status = TrustStatus.VERIFIED
                elif analysis.headers_grade in ["C", "D"]:
                    analysis.status = TrustStatus.SUSPICIOUS
                else:  # E, F
                    analysis.status = TrustStatus.HIGH_RISK
                
                # Parse individual headers
                headers = data.get("headers", [])
                
                # Key headers to check
                header_checklist = {
                    "Strict-Transport-Security": "HSTS",
                    "Content-Security-Policy": "CSP",
                    "X-Frame-Options": "X-Frame-Options",
                    "X-Content-Type-Options": "X-Content-Type-Options",
                    "Referrer-Policy": "Referrer-Policy"
                }
                
                for header_name, display_name in header_checklist.items():
                    found = False
                    for header in headers:
                        if header.get("name") == header_name:
                            found = True
                            analysis.security_headers_present.append(display_name)
                            
                            # Set boolean flags
                            if display_name == "HSTS":
                                analysis.has_hsts = True
                            elif display_name == "CSP":
                                analysis.has_csp = True
                            elif display_name == "X-Frame-Options":
                                analysis.has_x_frame_options = True
                            elif display_name == "X-Content-Type-Options":
                                analysis.has_x_content_type_options = True
                            elif display_name == "Referrer-Policy":
                                analysis.has_referrer_policy = True
                            break
                    
                    if not found:
                        analysis.security_headers_missing.append(display_name)
                
                # Generate flags
                if analysis.headers_grade == "F":
                    analysis.flags.append("No important security headers detected (grade F)")
                
                if not analysis.has_hsts:
                    analysis.flags.append("Missing HSTS header (no enforced HTTPS)")
                
                if not analysis.has_csp:
                    analysis.flags.append("Missing Content-Security-Policy header")
                
        except httpx.HTTPError as e:
            logger.error(f"HTTP error checking security headers: {e}")
            analysis.flags.append(f"Security headers check failed: {str(e)}")
            try:
                async with httpx.AsyncClient(timeout=15.0) as client:
                    await SecurityHeadersService._populate_headers_fallback(client, analysis, domain)
            except Exception:
                analysis.status = TrustStatus.UNKNOWN
                analysis.risk_score = 3

        except Exception as e:
            logger.error(f"Unexpected error in security headers analysis: {e}")
            analysis.status = TrustStatus.UNKNOWN
        
        # Cap at 10
        analysis.risk_score = min(analysis.risk_score, 10)
        
        return analysis

    @staticmethod
    async def _populate_headers_fallback(
        client: httpx.AsyncClient,
        analysis: SecurityHeadersAnalysis,
        domain: str
    ) -> None:
        """
        Fall back to a direct HEAD/GET request when the external grading API is
        unavailable, then derive a coarse grade from the headers we can see.
        """
        response = None
        for method in ("HEAD", "GET"):
            try:
                response = await client.request(method, f"https://{domain}", follow_redirects=True)
                if response.status_code < 500:
                    break
            except httpx.HTTPError:
                response = None

        if response is None:
            analysis.headers_grade = "UNKNOWN"
            analysis.flags.append("Could not analyze security headers")
            analysis.status = TrustStatus.UNKNOWN
            analysis.risk_score = 1
            return

        header_values = response.headers
        header_map = {
            "strict-transport-security": ("has_hsts", "HSTS"),
            "content-security-policy": ("has_csp", "CSP"),
            "x-frame-options": ("has_x_frame_options", "X-Frame-Options"),
            "x-content-type-options": ("has_x_content_type_options", "X-Content-Type-Options"),
            "referrer-policy": ("has_referrer_policy", "Referrer-Policy"),
        }

        present_count = 0
        for key, (attr_name, display_name) in header_map.items():
            if key in header_values:
                setattr(analysis, attr_name, True)
                analysis.security_headers_present.append(display_name)
                present_count += 1
            else:
                analysis.security_headers_missing.append(display_name)

        if present_count >= 4:
            analysis.headers_grade = "A"
            analysis.risk_score = 1
            analysis.status = TrustStatus.VERIFIED
        elif present_count >= 2:
            analysis.headers_grade = "C"
            analysis.risk_score = 3
            analysis.status = TrustStatus.SUSPICIOUS
        else:
            analysis.headers_grade = "F"
            analysis.risk_score = 8
            analysis.status = TrustStatus.HIGH_RISK

        analysis.flags.append("External security header API unavailable; using direct header probe instead")
