from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.routers import scan, report, geolocation

app = FastAPI(title="Sentryl API", description="AI-powered email threat detection")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan.router)
app.include_router(report.router)
app.include_router(geolocation.router)

@app.get("/")
async def root():
    return {"message": "Sentryl API is running"}
