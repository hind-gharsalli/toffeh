import whois
from datetime import datetime, timedelta
from models import WhoisAnalysis, TrustStatus
import logging

logger = logging.getLogger(__name__)

class WhoisService:
    
    @staticmethod
    async def analyze(domain: str) -> WhoisAnalysis:
        """
        Analyze WHOIS data for risk indicators
        """
        
        analysis = WhoisAnalysis(
            domain=domain,
            status=TrustStatus.UNKNOWN,
            risk_score=0,
            details={}
        )
        
        try:
            # Fetch WHOIS data
            whois_data = whois.whois(domain)
            
            # Extract key dates
            creation_date = whois_data.creation_date
            expiry_date = whois_data.expiry_date
            
            # Handle list returns (some registrars return lists)
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            
            analysis.registered_date = creation_date
            analysis.expiry_date = expiry_date
            
            # Calculate domain age
            if creation_date:
                age_delta = datetime.now(creation_date.tzinfo) - creation_date
                analysis.domain_age_days = age_delta.days
                
                # Check if recently registered (< 90 days)
                if analysis.domain_age_days < 90:
                    analysis.is_recently_registered = True
                    analysis.risk_score += 8
                    analysis.flags.append(
                        f"Domain registered only {analysis.domain_age_days} days ago"
                    )
                
                # Very new (< 30 days) = higher risk
                if analysis.domain_age_days < 30:
                    analysis.risk_score += 7  # Total: 15
                    analysis.flags.append("Domain is extremely new (< 30 days)")
            
            # Check expiry date
            if expiry_date:
                expiry_delta = expiry_date - datetime.now(expiry_date.tzinfo)
                if expiry_delta.days < 60:
                    analysis.is_expiring_soon = True
                    analysis.risk_score += 3
                    analysis.flags.append("Domain expiring soon (< 60 days)")
            
            # Extract registrar
            analysis.registrar = whois_data.registrar
            analysis.registrant_country = whois_data.country
            
            # Check if privacy protected
            if whois_data.registrant_email and "privacy" in str(whois_data.registrant_email).lower():
                analysis.is_privacy_protected = True
            
            # Suspicious registrars list
            suspicious_registrars = [
                "namecheap", "godaddy", "name.com", "123reg"
            ]
            
            if analysis.registrar and any(
                suspect in analysis.registrar.lower() 
                for suspect in suspicious_registrars
            ):
                analysis.flags.append(f"Registrar '{analysis.registrar}' commonly used for phishing")
                # Don't add extra points - these are legitimate registrars
            
            analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 10 else TrustStatus.VERIFIED
            analysis.details = {
                "creation_date": str(creation_date),
                "expiry_date": str(expiry_date),
                "registrar": analysis.registrar,
                "registrant_country": analysis.registrant_country,
                "privacy_protected": analysis.is_privacy_protected
            }
            
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            analysis.flags.append(f"Could not retrieve WHOIS data: {str(e)}")
            analysis.status = TrustStatus.UNKNOWN
            analysis.risk_score = 5  # Unknown = slight risk
        
        # Cap at 20
        analysis.risk_score = min(analysis.risk_score, 20)
        
        return analysis
