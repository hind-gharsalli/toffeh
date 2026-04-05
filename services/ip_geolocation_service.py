import httpx
import logging
from models import IpGeolocationAnalysis, TrustStatus
import socket

logger = logging.getLogger(__name__)

class IpGeolocationService:
    
    IP_API_URL = "http://ip-api.com/json"
    
    @staticmethod
    async def resolve_domain(domain: str) -> str:
        """
        Resolve domain to IP address
        """
        try:
            ip = socket.gethostbyname(domain)
            return ip
        except socket.gaierror as e:
            logger.error(f"Could not resolve {domain}: {e}")
            return None
    
    @staticmethod
    async def analyze(domain: str, claimed_origin: str = None) -> IpGeolocationAnalysis:
        """
        Analyze IP geolocation and compare to claimed origin
        Using ip-api.com (FREE, no key needed)
        """
        
        analysis = IpGeolocationAnalysis(
            ip_address="unknown",
            status=TrustStatus.UNKNOWN,
            risk_score=0,
            claimed_origin=claimed_origin
        )
        
        try:
            # Resolve domain to IP
            ip = await IpGeolocationService.resolve_domain(domain)
            
            if not ip:
                analysis.flags.append(f"Could not resolve domain to IP")
                analysis.risk_score = 3
                return analysis
            
            analysis.ip_address = ip
            
            # Get geolocation
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{IpGeolocationService.IP_API_URL}/{ip}",
                    params={"fields": "status,country,city,isp,org,as,proxy,mobile"}
                )
                
                if response.status_code != 200:
                    logger.warning(f"IP lookup failed for {ip}")
                    IpGeolocationService._populate_resolution_only_fallback(analysis)
                    return analysis
                
                data = response.json()
                
                if data.get("status") != "success":
                    logger.warning(f"IP lookup returned error: {data.get('message')}")
                    IpGeolocationService._populate_resolution_only_fallback(analysis)
                    return analysis
                
                # Extract geolocation
                analysis.country = data.get("country")
                analysis.city = data.get("city")
                analysis.isp = data.get("isp")
                analysis.org = data.get("org")
                analysis.asn = data.get("as")
                
                # Proxy/VPN/Tor detection
                analysis.is_vpn_proxy = data.get("proxy", False)
                
                if analysis.is_vpn_proxy:
                    analysis.risk_score += 10
                    analysis.flags.append("Server is behind VPN/proxy (anonymized)")
                
                # Check against known bulletproof hosters
                bulletproof_asns = [
                    "AS39798",  # ColoCrossing
                    "AS60781",  # LeaseWeb
                    "AS16125",  # Voxility
                    "AS21011"   # Ipxo
                ]
                
                if analysis.asn in bulletproof_asns:
                    analysis.is_bulletproof_hoster = True
                    analysis.risk_score += 8
                    analysis.flags.append(
                        f"Server hosted by {analysis.org} (known phishing hoster)"
                    )
                
                # Compare to claimed origin
                if claimed_origin and analysis.country:
                    if claimed_origin.lower() not in analysis.country.lower():
                        analysis.matches_claimed_origin = False
                        analysis.risk_score += 5
                        analysis.flags.append(
                            f"Server in {analysis.country}, claimed to be in {claimed_origin}"
                        )
                
                analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 5 else TrustStatus.VERIFIED
        
        except httpx.HTTPError as e:
            logger.error(f"HTTP error in IP geolocation: {e}")
            analysis.flags.append(f"IP geolocation lookup error: {str(e)}")
            IpGeolocationService._populate_resolution_only_fallback(analysis)
        
        except Exception as e:
            logger.error(f"Unexpected error in IP geolocation: {e}")
            IpGeolocationService._populate_resolution_only_fallback(analysis)
        
        # Cap at 10
        analysis.risk_score = min(analysis.risk_score, 10)
        
        return analysis

    @staticmethod
    def _populate_resolution_only_fallback(analysis: IpGeolocationAnalysis) -> None:
        """
        When the external geolocation service is unavailable, preserve the useful
        fact that the domain resolved to a public IP and mark the rest as unavailable.
        """
        analysis.country = analysis.country or "Unavailable"
        analysis.city = analysis.city or "Unavailable"
        analysis.isp = analysis.isp or "Unavailable"
        analysis.org = analysis.org or "Unavailable"
        analysis.asn = analysis.asn or "Unavailable"
        analysis.status = TrustStatus.UNKNOWN
        if "Geolocation service unavailable; using DNS resolution only" not in analysis.flags:
            analysis.flags.append("Geolocation service unavailable; using DNS resolution only")
