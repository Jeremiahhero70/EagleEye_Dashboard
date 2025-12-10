#!/usr/bin/env python3
"""
WazuhBoard - Pure Dashboard and Data API Layer for Wazuh Security Data
"""

import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse

from api import router as api_router

# Create FastAPI application
app = FastAPI(
    title="WazuhBoard",
    description="Pure dashboard and data API layer for Wazuh security statistics",
    version="1.0.0"
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include API router
app.include_router(api_router, prefix="/api")

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the main dashboard"""
    with open("static/index.html", "r") as f:
        return f.read()

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=False  # Disable reload to avoid startup issues
    )