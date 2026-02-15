from fastapi import APIRouter, BackgroundTasks, HTTPException, status
from typing import Dict, Any
import logging

from app.models.log import LogIngestRequest, LogIngestResponse, BaseLog
from app.services.elasticsearch_service import es_service
from app.services.ingestion_service import ingestion_service
from app.services.storage_service import storage_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])


@router.post(
    "/ingest",
    response_model=LogIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest logs",
    description="Accept logs for ingestion and process them asynchronously"
)
async def ingest_logs(
    request: LogIngestRequest,
    background_tasks: BackgroundTasks
) -> LogIngestResponse:
    """
    Ingest logs endpoint.
    
    - Validates incoming logs using Pydantic models
    - Returns 202 Accepted immediately
    - Processes logs in background task
    
    Args:
        request: Log ingestion request containing list of logs
        background_tasks: FastAPI background tasks manager
        
    Returns:
        LogIngestResponse with job ID and status
    """
    try:
        # Generate job ID for tracking
        job_id = ingestion_service.generate_job_id()
        logs_count = len(request.logs)
        
        # Add background task for processing
        background_tasks.add_task(
            ingestion_service.process_and_index_logs,
            request.logs
        )
        
        logger.info(f"Accepted {logs_count} logs for ingestion (Job ID: {job_id})")
        
        return LogIngestResponse(
            status="accepted",
            job_id=job_id,
            logs_count=logs_count,
            message=f"Accepted {logs_count} log(s) for processing"
        )
        
    except Exception as e:
        logger.error(f"Error in log ingestion: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to accept logs: {str(e)}"
        )


@router.get(
    "/health",
    summary="Health check",
    description="Check the health status of the log ingestion service and Elasticsearch connection"
)
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.
    
    Verifies:
    - Service is running
    - Elasticsearch connection is active
    
    Returns:
        Health status information
    """
    try:
        es_health = await es_service.health_check()
        
        return {
            "service": "FastAPI Log Ingestion",
            "status": "healthy" if es_health.get("status") == "connected" else "degraded",
            "elasticsearch": es_health,
            "storage": {
                "type": "file-based",
                "directory": str(storage_service.data_dir),
                "processed_logs": str(storage_service.processed_logs_file),
                "alerts": str(storage_service.alerts_file)
            }
        }
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {
            "service": "FastAPI Log Ingestion",
            "status": "unhealthy",
            "error": str(e)
        }
