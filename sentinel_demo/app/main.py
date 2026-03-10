from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request

from .state import app_state
from .routes import router

app = FastAPI(title="Sentinel Demo")

app.include_router(router)

app.mount("/static", StaticFiles(directory="sentinel_demo/app/static"), name="static")

templates = Jinja2Templates(directory="sentinel_demo/app/templates")


@app.get("/", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "state": app_state
        }
    )
