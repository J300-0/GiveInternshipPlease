from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime
from enum import IntEnum


class SeverityLevel(IntEnum):
    """OCSF Severity Levels"""
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6


class BaseLog(BaseModel):
    """
    Base log model following OCSF (Open Cybersecurity Schema Framework) standard.
    
    This model includes core OCSF fields that are common across all event types.
    """
    
    # Core OCSF Fields
    time: datetime = Field(..., description="The normalized event occurrence time")
    severity_id: int = Field(..., ge=0, le=6, description="The normalized severity level (0-6)")
    category_uid: int = Field(..., description="The category unique identifier")
    class_uid: int = Field(..., description="The class unique identifier")
    activity_id: int = Field(..., description="The normalized activity identifier")
    type_uid: int = Field(..., description="The event type unique identifier")
    
    # Optional Common Fields
    message: Optional[str] = Field(None, description="The event message or description")
    status: Optional[str] = Field(None, description="The event status")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional metadata")
    
    # Source Information
    src_endpoint: Optional[Dict[str, Any]] = Field(None, description="Source endpoint information")
    dst_endpoint: Optional[Dict[str, Any]] = Field(None, description="Destination endpoint information")
    
    class Config:
        json_schema_extra = {
            "example": {
                "time": "2026-02-15T12:00:00Z",
                "severity_id": 3,
                "category_uid": 4,
                "class_uid": 4001,
                "activity_id": 1,
                "type_uid": 400101,
                "message": "Network connection established",
                "status": "success"
            }
        }


class NetworkActivityLog(BaseLog):
    """
    Extended log model for network activity events.
    Category UID: 4 (Network Activity)
    """
    
    # Network-specific fields
    src_ip: Optional[str] = Field(None, description="Source IP address")
    src_port: Optional[int] = Field(None, description="Source port number")
    dst_ip: Optional[str] = Field(None, description="Destination IP address")
    dst_port: Optional[int] = Field(None, description="Destination port number")
    protocol: Optional[str] = Field(None, description="Network protocol (TCP, UDP, etc.)")
    bytes_in: Optional[int] = Field(None, description="Bytes received")
    bytes_out: Optional[int] = Field(None, description="Bytes sent")
    
    class Config:
        json_schema_extra = {
            "example": {
                "time": "2026-02-15T12:00:00Z",
                "severity_id": 2,
                "category_uid": 4,
                "class_uid": 4001,
                "activity_id": 1,
                "type_uid": 400101,
                "message": "Network connection established",
                "src_ip": "192.168.1.100",
                "src_port": 54321,
                "dst_ip": "10.0.0.50",
                "dst_port": 443,
                "protocol": "TCP"
            }
        }


class AuthenticationLog(BaseLog):
    """
    Extended log model for authentication events.
    Category UID: 3 (Identity & Access Management)
    """
    
    # Authentication-specific fields
    user: Optional[str] = Field(None, description="Username or user identifier")
    user_uid: Optional[str] = Field(None, description="Unique user identifier")
    auth_protocol: Optional[str] = Field(None, description="Authentication protocol")
    logon_type: Optional[str] = Field(None, description="Type of logon")
    is_mfa: Optional[bool] = Field(None, description="Whether MFA was used")
    session_uid: Optional[str] = Field(None, description="Session identifier")
    
    class Config:
        json_schema_extra = {
            "example": {
                "time": "2026-02-15T12:00:00Z",
                "severity_id": 2,
                "category_uid": 3,
                "class_uid": 3002,
                "activity_id": 1,
                "type_uid": 300201,
                "message": "User authentication successful",
                "user": "john.doe",
                "auth_protocol": "Kerberos",
                "is_mfa": True,
                "status": "success"
            }
        }


class LogIngestRequest(BaseModel):
    """
    Request model for log ingestion endpoint.
    Supports both single log and batch ingestion.
    """
    
    logs: List[BaseLog] = Field(..., description="List of logs to ingest")
    
    @validator('logs')
    def validate_logs_not_empty(cls, v):
        if not v:
            raise ValueError("At least one log must be provided")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "logs": [
                    {
                        "time": "2026-02-15T12:00:00Z",
                        "severity_id": 3,
                        "category_uid": 4,
                        "class_uid": 4001,
                        "activity_id": 1,
                        "type_uid": 400101,
                        "message": "Network connection established"
                    }
                ]
            }
        }


class LogIngestResponse(BaseModel):
    """Response model for log ingestion endpoint."""
    
    status: str = Field(..., description="Status of the ingestion request")
    job_id: str = Field(..., description="Background job identifier")
    logs_count: int = Field(..., description="Number of logs accepted for processing")
    message: str = Field(..., description="Human-readable message")
    
    class Config:
        json_schema_extra = {
            "example": {
                "status": "accepted",
                "job_id": "550e8400-e29b-41d4-a716-446655440000",
                "logs_count": 1,
                "message": "Logs accepted for processing"
            }
        }
