from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from app.api.endpoints import router

app = FastAPI(title="The Identity Project: Secure Email Summarizer")

# Mount API routes
app.include_router(router, prefix="/api")

# Mount Static Files (Frontend)
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("app/static/index.html")