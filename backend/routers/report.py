from fastapi import APIRouter, HTTPException
from typing import Dict, Any

router = APIRouter()

@router.get("/api/report/{report_id}")
async def get_report(report_id: str):
    # Stub for fetching a past report
    if report_id != "mock-id":
        raise HTTPException(status_code=404, detail="Report not found")
        
    return {"message": f"Report {report_id} details"}
