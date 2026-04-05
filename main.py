from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import logging
from datetime import datetime

from models import SourceCredibilityRequest, SourceCredibilityResponse
from services.orchestrator import SourceCredibilityOrchestrator

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Lifespan context manager
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Team B Source Credibility Service starting up")
    yield
    logger.info("Team B Source Credibility Service shutting down")

# Create FastAPI app
app = FastAPI(
    title="Team B: Source Credibility Analysis",
    description="Analyzes domain, IP, certificates, WHOIS, DNS history, and more",
    version="1.0.0",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================================
# ROUTES
# ============================================================================

@app.get("/", tags=["Health"])
async def root():
    """Root endpoint - health check"""
    return {
        "status": "online",
        "service": "Team B: Source Credibility Analysis",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health", tags=["Health"])
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }

@app.post(
    "/api/analyze-source",
    response_model=SourceCredibilityResponse,
    tags=["Analysis"]
)
async def analyze_source(request: SourceCredibilityRequest):
    """
    Main endpoint: Analyze source credibility
    
    Accepts:
    - URL: Full URL to analyze
    - domain: Domain name
    - source_account: Social media handle
    - username: Username for Sherlock search
    - current_text + historical_texts: optional stylometric consistency analysis
    
    Returns:
    - Complete source credibility analysis with trust score
    """
    
    logger.info(f"Received analysis request: {request}")
    
    try:
        # Validate input
        if not request.url and not request.domain:
            raise ValueError("Either 'url' or 'domain' must be provided")
        
        # Run orchestrator
        response = await SourceCredibilityOrchestrator.analyze(request)
        
        logger.info(f"Analysis successful: trust_score={response.trust_score}")
        
        return response
    
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    
    except Exception as e:
        logger.error(f"Unexpected error during analysis: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Analysis failed: {str(e)}"
        )

@app.post(
    "/api/batch-analyze",
    tags=["Analysis"]
)
async def batch_analyze(requests: list[SourceCredibilityRequest]):
    """
    Batch analysis endpoint (advanced)
    """
    
    logger.info(f"Received batch request with {len(requests)} domains")
    
    results = []
    
    for req in requests:
        try:
            result = await SourceCredibilityOrchestrator.analyze(req)
            results.append({
                "success": True,
                "data": result
            })
        except Exception as e:
            results.append({
                "success": False,
                "domain": req.domain or str(req.url),
                "error": str(e)
            })
    
    return {"results": results}

@app.get(
    "/api/docs/scoring",
    tags=["Documentation"]
)
async def scoring_documentation():
    """
    Returns explanation of the scoring system
    """
    return {
        "trust_score_breakdown": {
            "100": "Completely trustworthy",
            "80-99": "Mostly trustworthy",
            "60-79": "Some concerns",
            "40-59": "High risk",
            "0-39": "Very high risk / Phishing"
        },
        "scoring_components": {
            "WHOIS": "Domain registration age & details (0-20 points)",
            "DNS_History": "IP change frequency (0-15 points)",
            "SSL_Certificate": "Certificate age & issuer (0-15 points)",
            "IP_Geolocation": "Server location vs claimed origin (0-10 points)",
            "Security_Headers": "HTTP security headers (0-10 points)",
            "User_Reputation": "Social media presence (0-15 points, optional)",
            "Stylometry": "Writing-style consistency vs historical samples (0-10 points, optional)"
        },
        "total_possible_risk": 100,
        "formula": "trust_score = 100 - raw_risk_score"
    }

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "timestamp": datetime.now().isoformat()}
    )

@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "timestamp": datetime.now().isoformat()
        }
    )

# ============================================================================
# Run the app
# ============================================================================

if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8002,  # Team B runs on port 8002
        log_level="info"
    )
