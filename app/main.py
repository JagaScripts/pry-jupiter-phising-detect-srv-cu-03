from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.rules import router as rules_router

app = FastAPI(
    title="Jupiter Phishing Detect - Reputation Service",
    description="Microservicio v2 para gestión de alertas y dominios",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(rules_router, prefix="/api/v1")

@app.get("/health")
def health_check():
    return {"status": "ok", "service": "srv-reputation"}
