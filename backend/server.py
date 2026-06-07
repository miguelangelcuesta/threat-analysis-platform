from fastapi import FastAPI, APIRouter, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from datetime import datetime
from dotenv import load_dotenv
from pathlib import Path

from backend.analysis_engine import analyze_text
from backend.soc.database import engine, Base
# =====================
# APP
# =====================

app = FastAPI(
    title="Anti-Scam Detector API",
    version="1.0.0"
)

api = APIRouter(prefix="/api")

# =====================
# STARTUP (CORRECTO)
# =====================

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

# =====================
# ENV
# =====================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

# =====================
# CORS
# =====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
async def analyze(data: AnalyzeRequest, x_device_id: str = Header(default="anonymous")):

    try:
        content = data.text or data.url or ""

        if not content.strip():
            raise HTTPException(status_code=400, detail="Empty input")

        analysis = analyze_text(content)

        return {
            "id": datetime.now().strftime("%Y%m%d%H%M%S"),
            "device": x_device_id,
            **analysis
        }

    except Exception as e:
        import traceback
        print("\n🔥 FULL BACKEND ERROR:\n")
        print(traceback.format_exc())

        raise HTTPException(
            status_code=500,
            detail=str(e)
        )
# =====================
# ENDPOINTS AUX
# =====================

@api.get("/history")
async def history():
    return []

@api.get("/stats")
async def stats():
    return {
        "total_scans": 1,
        "threats_detected": 0,
        "status": "active"
    }

@api.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/health")
async def health_root():
    return {"status": "ok"}


@api.get("/")
async def root():
    return {"message": "Anti-Scam Detector API running"}

# =====================
# ROUTER
# =====================

app.include_router(api)