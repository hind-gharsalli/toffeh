import httpx
import logging
import socket
from models import DnsHistoryAnalysis, TrustStatus

logger = logging.getLogger(__name__)

class DnsHistoryService:
    
    CIRCL_PDNS_URL = "https://www.circl.lu/pdns/query"
    
    @staticmethod
    async def analyze(domain: str) -> DnsHistoryAnalysis:
        """
        Query CIRCL pDNS for DNS history (FREE, no key needed)
        """
        
        analysis = DnsHistoryAnalysis(
            domain=domain,
            status=TrustStatus.UNKNOWN,
            risk_score=0
        )
        
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(
                    f"{DnsHistoryService.CIRCL_PDNS_URL}/{domain}",
                    headers={"Accept": "application/json"}
                )
                
                if response.status_code != 200:
                    logger.warning(f"CIRCL pDNS lookup failed for {domain}")
                    DnsHistoryService._populate_dns_fallback(analysis, domain)
                    return analysis
                
                data = response.json()
                
                # Parse results
                rrsets = data.get("rrsets", [])
                
                # Extract A records (IPv4)
                seen_ips = {}
                for rrset in rrsets:
                    if rrset.get("type") == "A":
                        rdata = rrset.get("rdata", [])
                        timestamp = rrset.get("time_first")
                        
                        for ip in rdata:
                            if ip not in seen_ips:
                                seen_ips[ip] = timestamp
                            analysis.historical_ips.append(ip)
                
                # Get current IP
                if seen_ips:
                    latest_ip = max(seen_ips.items(), key=lambda x: x[1])[0]
                    analysis.current_ips = [latest_ip]
                
                # Check for frequent IP changes
                unique_ips = len(set(analysis.historical_ips))
                if unique_ips > 5:
                    analysis.recent_changes = unique_ips
                    analysis.has_suspicious_ip_change = True
                    analysis.risk_score += 8
                    analysis.flags.append(
                        f"Domain has {unique_ips} different IPs (suspicious frequency)"
                    )
                elif unique_ips > 2:
                    analysis.recent_changes = unique_ips
                    analysis.risk_score += 5
                    analysis.flags.append(f"Domain IP changed {unique_ips} times")
                
                # Check for NS changes
                ns_records = [r for r in rrsets if r.get("type") == "NS"]
                if ns_records:
                    analysis.nameserver_changes = len(ns_records)
                    if analysis.nameserver_changes > 2:
                        analysis.flags.append(
                            f"Nameserver changed {analysis.nameserver_changes} times"
                        )
                        analysis.risk_score += 3
                
                analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 5 else TrustStatus.VERIFIED
        
        except httpx.HTTPError as e:
            logger.error(f"HTTP error querying CIRCL pDNS: {e}")
            analysis.flags.append(f"DNS history lookup error: {str(e)}")
            DnsHistoryService._populate_dns_fallback(analysis, domain)

        except Exception as e:
            logger.error(f"Unexpected error in DNS history analysis: {e}")
            DnsHistoryService._populate_dns_fallback(analysis, domain)
        
        # Cap at 15
        analysis.risk_score = min(analysis.risk_score, 15)
        
        return analysis

    @staticmethod
    def _populate_dns_fallback(analysis: DnsHistoryAnalysis, domain: str) -> None:
        """
        Fall back to live DNS resolution when passive DNS history is unavailable.
        This keeps the service useful in constrained environments and preserves
        a minimally informative result for callers and tests.
        """
        try:
            resolved = socket.gethostbyname_ex(domain)
            ips = list(dict.fromkeys(resolved[2]))
            if ips:
                analysis.current_ips = ips
                analysis.historical_ips = ips.copy()
                analysis.status = TrustStatus.VERIFIED
                analysis.flags.append("Passive DNS unavailable; using live DNS resolution instead")
            else:
                analysis.status = TrustStatus.UNKNOWN
                analysis.flags.append("Could not retrieve DNS history")
        except socket.gaierror:
            analysis.status = TrustStatus.UNKNOWN
            analysis.flags.append("Could not retrieve DNS history")
