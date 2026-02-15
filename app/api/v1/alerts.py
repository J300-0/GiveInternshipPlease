from fastapi import APIRouter, HTTPException, Query
from typing import Optional
import logging

from app.models.alert import AlertListResponse, AlertResponse, Alert
from app.services.elasticsearch_service import es_service
from app.services.detection_service import detection_service

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.post("/detection/run")
async def run_detection(
    window_minutes: int = Query(default=5, ge=1, le=60, description="Time window in minutes"),
    threshold: float = Query(default=0.85, ge=0.0, le=1.0, description="Anomaly score threshold"),
    algorithm: str = Query(default="ecod", regex="^(ecod|iforest)$", description="Detection algorithm")
):
    """
    Trigger anomaly detection on recent logs.
    
    This endpoint:
    1. Queries logs from the last N minutes
    2. Extracts statistical features
    3. Runs PyOD anomaly detection
    4. Generates Alert objects for anomalies above threshold
    5. Stores alerts in Elasticsearch
    
    **For AI/MCP Integration**: This endpoint can be called periodically
    or triggered by external monitoring systems.
    
    Args:
        window_minutes: Time window to analyze (1-60 minutes)
        threshold: Anomaly score threshold (0.0-1.0)
        algorithm: Detection algorithm ('ecod' or 'iforest')
        
    Returns:
        Detection results summary including alert IDs
    """
    try:
        logger.info(f"Detection triggered: window={window_minutes}min, threshold={threshold}, algo={algorithm}")
        
        result = await detection_service.run_detection(
            window_minutes=window_minutes,
            threshold=threshold,
            algorithm=algorithm
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Error running detection: {e}")
        raise HTTPException(status_code=500, detail=f"Detection failed: {str(e)}")


@router.get("/", response_model=AlertListResponse)
async def list_alerts(
    page: int = Query(default=1, ge=1, description="Page number"),
    page_size: int = Query(default=10, ge=1, le=100, description="Alerts per page"),
    severity: Optional[int] = Query(default=None, ge=0, le=4, description="Filter by severity"),
    status: Optional[str] = Query(default=None, description="Filter by status"),
    category: Optional[str] = Query(default=None, description="Filter by category")
):
    """
    List alerts with filtering and pagination.
    
    **For AI/MCP Integration**: This endpoint provides structured alert data
    that AI agents can query and analyze.
    
    Filters:
    - severity: 0=UNKNOWN, 1=LOW, 2=MEDIUM, 3=HIGH, 4=CRITICAL
    - status: new, investigating, confirmed, false_positive, resolved
    - category: auth_anomaly, network_anomaly, general_anomaly
    
    Args:
        page: Page number (1-indexed)
        page_size: Number of alerts per page
        severity: Filter by severity level
        status: Filter by status
        category: Filter by category
        
    Returns:
        Paginated list of alerts
    """
    try:
        result = await es_service.query_alerts(
            page=page,
            page_size=page_size,
            severity=severity,
            status=status,
            category=category
        )
        
        # Convert to Pydantic models
        alerts = [Alert(**alert_data) for alert_data in result["alerts"]]
        
        return AlertListResponse(
            total=result["total"],
            page=result["page"],
            page_size=result["page_size"],
            alerts=alerts
        )
        
    except Exception as e:
        logger.error(f"Error listing alerts: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alerts: {str(e)}")


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str):
    """
    Retrieve a specific alert by ID.
    
    **For AI/MCP Integration**: This endpoint provides detailed alert information
    including context logs for investigation.
    
    Args:
        alert_id: Unique alert identifier
        
    Returns:
        Alert object with full context
    """
    try:
        alert_data = await es_service.get_alert_by_id(alert_id)
        
        if not alert_data:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        alert = Alert(**alert_data)
        
        return AlertResponse(alert=alert)
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alert: {str(e)}")


@router.get("/{alert_id}/context")
async def get_alert_context(alert_id: str):
    """
    Get detailed context for an alert including related logs.
    
    **For AI/MCP Integration**: This endpoint provides additional context
    that AI agents can use for investigation and playbook generation.
    
    Args:
        alert_id: Unique alert identifier
        
    Returns:
        Alert with expanded context information
    """
    try:
        alert_data = await es_service.get_alert_by_id(alert_id)
        
        if not alert_data:
            raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
        
        # Return full alert with context logs
        return {
            "alert_id": alert_id,
            "alert": alert_data,
            "context_summary": {
                "affected_entities": alert_data.get("affected_entities", {}),
                "detection_window": {
                    "start": alert_data.get("detection_window_start"),
                    "end": alert_data.get("detection_window_end")
                },
                "features": alert_data.get("features", {}),
                "context_logs_count": len(alert_data.get("context_logs", []))
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving alert context {alert_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to retrieve alert context: {str(e)}")
