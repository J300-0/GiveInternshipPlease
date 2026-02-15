from fastapi import APIRouter
from .logs import router as logs_router
from .alerts import router as alerts_router
from .playbooks import router as playbooks_router

# Create v1 API router
api_v1_router = APIRouter(prefix="/api/v1")

# Include sub-routers
api_v1_router.include_router(logs_router)
api_v1_router.include_router(alerts_router)
api_v1_router.include_router(playbooks_router)

__all__ = ["api_v1_router"]
