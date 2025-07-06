from fastapi import FastAPI
from fastapi.responses import FileResponse

from src.api import susi
from src.dependencies import lifespan

app = FastAPI(lifespan=lifespan)
app.include_router(susi.router)


@app.get("/")
def get_root() -> FileResponse:
    return FileResponse(path="./src/static/susi.html")
