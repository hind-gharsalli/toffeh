import logging
import subprocess
import json
from models import UserReputationAnalysis, TrustStatus

logger = logging.getLogger(__name__)

class UserReputationService:
    
    @staticmethod
    async def analyze(username: str) -> UserReputationAnalysis:
        """
        Use Sherlock to search for the username across platforms
        """
        normalized_username = (username or "").strip().lstrip("@")
        
        analysis = UserReputationAnalysis(
            username=normalized_username,
            status=TrustStatus.UNKNOWN,
            risk_score=0
        )

        if not normalized_username:
            analysis.flags.append("No username provided for reputation analysis")
            return analysis
        
        try:
            # Run Sherlock
            result = subprocess.run(
                [
                    "sherlock",
                    "--json",
                    "--timeout", "10",
                    normalized_username
                ],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Parse JSON output
                data = json.loads(result.stdout)
                
                # data = {username: {platform: {url: ..., status: ...}}}
                user_data = data.get(normalized_username, {})
                
                for platform, details in user_data.items():
                    if details.get("status") == "Claimed":
                        url = details.get("url", "")
                        analysis.platforms_found[platform] = url
                
                # Less platforms found = more suspicious
                platform_count = len(analysis.platforms_found)
                if platform_count == 0:
                    analysis.is_new_account = True
                    analysis.risk_score += 8
                    analysis.flags.append("Username not found on any major platform")
                elif platform_count == 1:
                    analysis.risk_score += 4
                    analysis.flags.append("Username found on only one platform")
                else:
                    analysis.flags.append(f"Username found on {platform_count} platforms")
                
                analysis.status = TrustStatus.SUSPICIOUS if analysis.risk_score > 5 else TrustStatus.VERIFIED
            
            else:
                logger.warning(f"Sherlock search failed for {normalized_username}")
                analysis.flags.append("Could not search for username on social platforms")
                analysis.status = TrustStatus.UNKNOWN
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Sherlock timeout for {normalized_username}")
            analysis.flags.append("Sherlock search timed out")
        
        except FileNotFoundError:
            logger.warning("Sherlock not installed. Install with: pip install sherlock-project")
            analysis.flags.append("Sherlock not available (optional feature)")
        
        except json.JSONDecodeError:
            logger.error("Could not parse Sherlock JSON output")
            analysis.status = TrustStatus.UNKNOWN
        
        except Exception as e:
            logger.error(f"Unexpected error in user reputation analysis: {e}")
            analysis.status = TrustStatus.UNKNOWN
        
        # Cap at 15
        analysis.risk_score = min(analysis.risk_score, 15)
        
        return analysis
