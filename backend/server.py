from fastapi import FastAPI, APIRouter, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

from analysis_engine import analyze_text

# =====================
# ENV
# =====================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# =====================
# APP
# =====================

app = FastAPI(
    title="Anti-Scam Detector API",
    version="1.0.0"
)

api = APIRouter(prefix="/api")

# =====================
# CORS
# =====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # para frontend público
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================
# REQUEST MODEL
# =====================

class AnalyzeRequest(BaseModel):
    text: str | None = Field(default=None, max_length=3000)
    url: str | None = Field(default=None, max_length=2000)
    input_type: str | None = "text"

# =====================
# ANALYZE ROUTE
# =====================

@api.post("/analyze")
async def analyze(
    data: AnalyzeRequest,
    x_device_id: str = Header(default="anonymous")
):

    try:

        content = data.text or data.url or ""

        if not content.strip():
            raise HTTPException(
                status_code=400,
                detail="Empty input"
            )

        analysis = analyze_text(content)

        return {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "device": x_device_id,
            **analysis
        }

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Analysis engine error: {str(e)}"
        )

# =====================
# HISTORY (mock)
# =====================

@api.get("/history")
async def history():
    return []

# =====================
# STATS (mock)
# =====================

@api.get("/stats")
async def stats():
    return {
        "total_scans": 1,
        "threats_detected": 0,
        "status": "active"
    }

# =====================
# HEALTH
# =====================

@api.get("/health")
async def health():
    return {
        "status": "ok"
    }

# =====================
# ROOT
# =====================

@api.get("/")
async def root():
    return {
        "message": "Anti-Scam Detector API running"
    }

# =====================
# ROUTER
# =====================

app.include_router(api)