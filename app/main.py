from fastapi import FastAPI
from app.api.api_v1.endpoints.routers import router as authorization_routes

app = FastAPI()
app.include_router(router=authorization_routes, prefix="")
