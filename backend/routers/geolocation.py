from fastapi import APIRouter
from backend.services.ip_intel import analyze_ip

router = APIRouter()

@router.get("/api/geo/{ip}")
async def get_geolocation(ip: str):
    return analyze_ip(ip)
