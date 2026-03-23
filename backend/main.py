from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.endpoints import router
from app.core.database import init_db

app = FastAPI(title="The Identity Project: Secure Email Summarizer")

# Mount API routes
app.include_router(router, prefix="/api")

# Mount Static Files (Frontend)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("app/static/index.html")
@app.get("/dashboard", response_class=FileResponse)

async def serve_dashboard():
    """Serves the CISO analytics dashboard page."""
    return "app/static/dashboard.html"

@app.on_event("startup")
async def on_startup():
    await init_db()