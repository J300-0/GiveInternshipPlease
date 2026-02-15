from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import IntEnum


class AlertSeverity(IntEnum):
    """Alert severity levels based on anomaly score and impact"""
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class AlertStatus(str):
    """Alert lifecycle status"""
    NEW = "new"
    INVESTIGATING = "investigating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class AnomalyContext(BaseModel):
    """
    Context information for an anomaly.
    Contains related log entries that contributed to the detection.
    """
    log_id: str = Field(..., description="Elasticsearch document ID of the related log")
    timestamp: datetime = Field(..., description="When the log occurred")
    severity_id: int = Field(..., description="Log severity level")
    message: str = Field(..., description="Log message")
    
    # Optional fields from the log
    src_ip: Optional[str] = Field(None, description="Source IP if network event")
    dst_ip: Optional[str] = Field(None, description="Destination IP if network event")
    user: Optional[str] = Field(None, description="User if authentication event")
    
    class Config:
        json_schema_extra = {
            "example": {
                "log_id": "abc123",
                "timestamp": "2026-02-15T12:00:00Z",
                "severity_id": 4,
                "message": "Failed login attempt",
                "user": "admin",
                "src_ip": "203.0.113.45"
            }
        }


class Alert(BaseModel):
    """
    Alert model representing a detected anomaly.
    
    This schema is designed for AI/MCP consumption and contains:
    - Anomaly detection metadata (score, algorithm used)
    - Affected entities (IPs, users, etc.)
    - Context logs for investigation
    - Severity and status for prioritization
    """
    
    # Core Alert Fields
    alert_id: str = Field(..., description="Unique alert identifier")
    created_at: datetime = Field(..., description="When the alert was created")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    # Detection Metadata
    anomaly_score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score from detection algorithm (0-1)")
    detection_algorithm: str = Field(..., description="Algorithm used for detection (e.g., ECOD, IsolationForest)")
    threshold: float = Field(..., description="Threshold used for alerting")
    
    # Alert Classification
    severity: AlertSeverity = Field(..., description="Alert severity level")
    status: str = Field(default=AlertStatus.NEW, description="Current alert status")
    category: str = Field(..., description="Alert category (e.g., network_anomaly, auth_anomaly)")
    
    # Affected Entities
    affected_entities: Dict[str, List[str]] = Field(
        default_factory=dict,
        description="Entities involved in the anomaly (e.g., {'ips': ['1.2.3.4'], 'users': ['admin']})"
    )
    
    # Context for Investigation
    context_logs: List[AnomalyContext] = Field(
        default_factory=list,
        description="Related log entries that triggered this alert"
    )
    
    # Time Window
    detection_window_start: datetime = Field(..., description="Start of the detection time window")
    detection_window_end: datetime = Field(..., description="End of the detection time window")
    
    # Statistical Features (for AI analysis)
    features: Dict[str, float] = Field(
        default_factory=dict,
        description="Extracted statistical features used in detection"
    )
    
    # Human-readable summary
    summary: str = Field(..., description="Brief summary of the anomaly")
    description: Optional[str] = Field(None, description="Detailed description of what was detected")
    
    # Metadata
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata for extensibility"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert_id": "alert-550e8400-e29b-41d4-a716-446655440000",
                "created_at": "2026-02-15T12:05:00Z",
                "updated_at": "2026-02-15T12:05:00Z",
                "anomaly_score": 0.92,
                "detection_algorithm": "ECOD",
                "threshold": 0.85,
                "severity": 4,
                "status": "new",
                "category": "auth_anomaly",
                "affected_entities": {
                    "users": ["admin"],
                    "ips": ["203.0.113.45"]
                },
                "context_logs": [
                    {
                        "log_id": "log-123",
                        "timestamp": "2026-02-15T12:00:00Z",
                        "severity_id": 4,
                        "message": "Failed login attempt",
                        "user": "admin",
                        "src_ip": "203.0.113.45"
                    }
                ],
                "detection_window_start": "2026-02-15T12:00:00Z",
                "detection_window_end": "2026-02-15T12:05:00Z",
                "features": {
                    "failed_login_count": 15.0,
                    "unique_source_ips": 1.0,
                    "time_variance": 0.05
                },
                "summary": "Unusual authentication activity detected for user 'admin'",
                "description": "15 failed login attempts from single IP in 5 minutes"
            }
        }


class AlertListResponse(BaseModel):
    """Response model for listing alerts"""
    total: int = Field(..., description="Total number of alerts")
    page: int = Field(..., description="Current page number")
    page_size: int = Field(..., description="Number of alerts per page")
    alerts: List[Alert] = Field(..., description="List of alerts")
    
    class Config:
        json_schema_extra = {
            "example": {
                "total": 42,
                "page": 1,
                "page_size": 10,
                "alerts": []
            }
        }


class AlertResponse(BaseModel):
    """Response model for single alert retrieval"""
    alert: Alert = Field(..., description="The alert object")
    
    class Config:
        json_schema_extra = {
            "example": {
                "alert": {
                    "alert_id": "alert-550e8400",
                    "anomaly_score": 0.92,
                    "severity": 4,
                    "summary": "Unusual authentication activity detected"
                }
            }
        }


class AlertCreateRequest(BaseModel):
    """Request model for creating alerts (used internally by detection service)"""
    anomaly_score: float = Field(..., ge=0.0, le=1.0)
    detection_algorithm: str
    threshold: float
    severity: AlertSeverity
    category: str
    affected_entities: Dict[str, List[str]] = Field(default_factory=dict)
    context_log_ids: List[str] = Field(default_factory=list)
    detection_window_start: datetime
    detection_window_end: datetime
    features: Dict[str, float] = Field(default_factory=dict)
    summary: str
    description: Optional[str] = None
