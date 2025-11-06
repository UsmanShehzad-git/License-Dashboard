from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from src.dashboard.api import router as dashboard_router
import uvicorn

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")

app.include_router(dashboard_router)

if __name__ == "__main__":
    uvicorn.run("main:app", reload=True)