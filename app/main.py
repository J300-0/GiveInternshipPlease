"""
Main FastAPI Application - Hybrid Workflow
Elasticsearch for input → Processing → File output for AI
"""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import logging

from app.core.config import settings
from app.api.v1 import api_v1_router
from app.services.elasticsearch_service import es_service
from app.services.storage_service import storage_service

# Configure logging
logging.basicConfig(
    level=logging.INFO if not settings.debug else logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Application lifespan manager
    Handles startup and shutdown events
    """
    # Startup
    logger.info("Starting FastAPI Log Ingestion Service (Hybrid Mode)...")
    
    try:
        # Try to connect to Elasticsearch (optional)
        try:
            await es_service.connect()
            await es_service.create_index()
            await es_service.create_alerts_index()
            logger.info("Elasticsearch connected")
        except Exception as e:
            logger.warning(f"Elasticsearch not available, using file-only mode: {e}")
        
        # Initialize storage service
        logger.info(f"File storage initialized at {storage_service.data_dir}")
        logger.info("Application startup complete")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        # Don't raise - allow app to start in file-only mode
    
    yield
    
    # Shutdown
    logger.info("Shutting down FastAPI Log Ingestion Service...")
    
    try:
        await es_service.disconnect()
        logger.info("Application shutdown complete")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")


# Create FastAPI application
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Hybrid log ingestion: Elasticsearch + File-based output for AI",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(api_v1_router)


# Root endpoint
@app.get("/", tags=["root"])
async def root():
    """Root endpoint with API information"""
    es_status = "connected" if es_service.client else "file-only mode"
    return {
        "service": settings.app_name,
        "version": settings.app_version,
        "status": "running",
        "mode": "hybrid",
        "elasticsearch": es_status,
        "storage": str(storage_service.data_dir),
        "docs": "/docs",
        "health": "/api/v1/logs/health"
    }


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Handle unexpected exceptions"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": "Internal server error",
            "error": str(exc) if settings.debug else "An error occurred"
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
