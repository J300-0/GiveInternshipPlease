from typing import List, Dict, Any, Optional
import logging
from datetime import datetime, timedelta
import uuid
import pandas as pd
import numpy as np
from pyod.models.ecod import ECOD
from pyod.models.iforest import IForest

from app.services.elasticsearch_service import es_service
from app.models.alert import Alert, AlertSeverity, AlertStatus, AnomalyContext, AlertCreateRequest

logger = logging.getLogger(__name__)


class DetectionService:
    """
    Statistical anomaly detection service using PyOD.
    
    This service:
    1. Queries recent logs from Elasticsearch
    2. Extracts statistical features
    3. Runs PyOD models (ECOD, Isolation Forest)
    4. Generates Alert objects when anomalies detected
    """
    
    def __init__(self):
        self.default_threshold = 0.85
        self.default_window_minutes = 5
    
    async def run_detection(
        self,
        window_minutes: int = None,
        threshold: float = None,
        algorithm: str = "ecod"
    ) -> Dict[str, Any]:
        """
        Run anomaly detection on recent logs.
        
        Args:
            window_minutes: Time window to analyze (default: 5 minutes)
            threshold: Anomaly score threshold (default: 0.85)
            algorithm: Detection algorithm to use ('ecod' or 'iforest')
            
        Returns:
            Detection results summary
        """
        window_minutes = window_minutes or self.default_window_minutes
        threshold = threshold or self.default_threshold
        
        try:
            logger.info(f"Starting detection with {algorithm}, window={window_minutes}min, threshold={threshold}")
            
            # Step 1: Query recent logs
            end_time = datetime.utcnow()
            start_time = end_time - timedelta(minutes=window_minutes)
            
            logs = await es_service.query_recent_logs(
                start_time=start_time,
                end_time=end_time,
                size=1000
            )
            
            if not logs or len(logs) < 10:
                logger.info(f"Insufficient logs for detection: {len(logs) if logs else 0} logs found")
                return {
                    "status": "skipped",
                    "reason": "insufficient_data",
                    "logs_analyzed": len(logs) if logs else 0,
                    "alerts_generated": 0
                }
            
            logger.info(f"Analyzing {len(logs)} logs from {start_time} to {end_time}")
            
            # Step 2: Extract features
            features_df = self._extract_features(logs)
            
            if features_df.empty or len(features_df) < 10:
                logger.warning("Feature extraction resulted in insufficient data")
                return {
                    "status": "skipped",
                    "reason": "feature_extraction_failed",
                    "logs_analyzed": len(logs),
                    "alerts_generated": 0
                }
            
            # Step 3: Run PyOD model
            anomaly_scores, anomaly_labels = self._run_pyod_model(features_df, algorithm)
            
            # Step 4: Generate alerts for anomalies above threshold
            alerts_created = []
            anomaly_indices = np.where(anomaly_scores >= threshold)[0]
            
            logger.info(f"Found {len(anomaly_indices)} anomalies above threshold {threshold}")
            
            for idx in anomaly_indices:
                alert = await self._create_alert_from_anomaly(
                    log_index=idx,
                    logs=logs,
                    anomaly_score=float(anomaly_scores[idx]),
                    features=features_df.iloc[idx].to_dict(),
                    algorithm=algorithm,
                    threshold=threshold,
                    start_time=start_time,
                    end_time=end_time
                )
                
                if alert:
                    alerts_created.append(alert)
            
            return {
                "status": "completed",
                "logs_analyzed": len(logs),
                "features_extracted": len(features_df),
                "anomalies_detected": len(anomaly_indices),
                "alerts_generated": len(alerts_created),
                "alert_ids": [a["alert_id"] for a in alerts_created],
                "algorithm": algorithm,
                "threshold": threshold,
                "window_minutes": window_minutes
            }
            
        except Exception as e:
            logger.error(f"Error in detection: {e}", exc_info=True)
            return {
                "status": "failed",
                "error": str(e),
                "logs_analyzed": 0,
                "alerts_generated": 0
            }
    
    def _extract_features(self, logs: List[Dict[str, Any]]) -> pd.DataFrame:
        """
        Extract statistical features from logs for anomaly detection.
        
        This is a simplified feature extraction. In production, you'd use
        tsfresh for more sophisticated time-series features.
        
        Args:
            logs: List of log dictionaries
            
        Returns:
            DataFrame with extracted features
        """
        try:
            features_list = []
            
            for log in logs:
                features = {
                    # Basic features
                    "severity_id": log.get("severity_id", 0),
                    "category_uid": log.get("category_uid", 0),
                    "class_uid": log.get("class_uid", 0),
                    
                    # Network features (if available)
                    "has_src_ip": 1 if log.get("src_ip") else 0,
                    "has_dst_ip": 1 if log.get("dst_ip") else 0,
                    "src_port": log.get("src_port", 0) or 0,
                    "dst_port": log.get("dst_port", 0) or 0,
                    "bytes_in": log.get("bytes_in", 0) or 0,
                    "bytes_out": log.get("bytes_out", 0) or 0,
                    
                    # Auth features (if available)
                    "has_user": 1 if log.get("user") else 0,
                    "is_mfa": 1 if log.get("is_mfa") else 0,
                    
                    # Temporal features
                    "hour_of_day": self._extract_hour(log.get("time")),
                }
                
                features_list.append(features)
            
            df = pd.DataFrame(features_list)
            
            # Fill NaN values with 0
            df = df.fillna(0)
            
            logger.debug(f"Extracted features shape: {df.shape}")
            return df
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return pd.DataFrame()
    
    def _extract_hour(self, timestamp_str: Optional[str]) -> int:
        """Extract hour of day from timestamp string"""
        try:
            if timestamp_str:
                dt = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                return dt.hour
        except:
            pass
        return 0
    
    def _run_pyod_model(self, features_df: pd.DataFrame, algorithm: str) -> tuple:
        """
        Run PyOD anomaly detection model.
        
        Args:
            features_df: DataFrame with features
            algorithm: 'ecod' or 'iforest'
            
        Returns:
            Tuple of (anomaly_scores, anomaly_labels)
        """
        try:
            X = features_df.values
            
            if algorithm == "ecod":
                model = ECOD(contamination=0.1)
            elif algorithm == "iforest":
                model = IForest(contamination=0.1, random_state=42)
            else:
                logger.warning(f"Unknown algorithm {algorithm}, defaulting to ECOD")
                model = ECOD(contamination=0.1)
            
            # Fit and predict
            model.fit(X)
            anomaly_scores = model.decision_scores_
            anomaly_labels = model.labels_
            
            # Normalize scores to 0-1 range
            if len(anomaly_scores) > 0:
                min_score = anomaly_scores.min()
                max_score = anomaly_scores.max()
                if max_score > min_score:
                    anomaly_scores = (anomaly_scores - min_score) / (max_score - min_score)
            
            logger.info(f"PyOD {algorithm} completed. Score range: {anomaly_scores.min():.3f} - {anomaly_scores.max():.3f}")
            
            return anomaly_scores, anomaly_labels
            
        except Exception as e:
            logger.error(f"Error running PyOD model: {e}")
            return np.array([]), np.array([])
    
    async def _create_alert_from_anomaly(
        self,
        log_index: int,
        logs: List[Dict[str, Any]],
        anomaly_score: float,
        features: Dict[str, float],
        algorithm: str,
        threshold: float,
        start_time: datetime,
        end_time: datetime
    ) -> Optional[Dict[str, Any]]:
        """
        Create an Alert object from detected anomaly.
        
        Args:
            log_index: Index of the anomalous log
            logs: All logs analyzed
            anomaly_score: Anomaly score from PyOD
            features: Extracted features
            algorithm: Algorithm used
            threshold: Threshold used
            start_time: Detection window start
            end_time: Detection window end
            
        Returns:
            Alert dictionary or None
        """
        try:
            anomalous_log = logs[log_index]
            alert_id = f"alert-{uuid.uuid4()}"
            
            # Determine severity based on anomaly score
            if anomaly_score >= 0.95:
                severity = AlertSeverity.CRITICAL
            elif anomaly_score >= 0.90:
                severity = AlertSeverity.HIGH
            elif anomaly_score >= 0.85:
                severity = AlertSeverity.MEDIUM
            else:
                severity = AlertSeverity.LOW
            
            # Extract affected entities
            affected_entities = {}
            if anomalous_log.get("src_ip"):
                affected_entities.setdefault("ips", []).append(anomalous_log["src_ip"])
            if anomalous_log.get("dst_ip"):
                affected_entities.setdefault("ips", []).append(anomalous_log["dst_ip"])
            if anomalous_log.get("user"):
                affected_entities.setdefault("users", []).append(anomalous_log["user"])
            
            # Determine category
            category_uid = anomalous_log.get("category_uid", 0)
            if category_uid == 3:
                category = "auth_anomaly"
            elif category_uid == 4:
                category = "network_anomaly"
            else:
                category = "general_anomaly"
            
            # Create context from the anomalous log
            context_logs = [
                AnomalyContext(
                    log_id=anomalous_log.get("_id", f"log-{log_index}"),
                    timestamp=datetime.fromisoformat(anomalous_log["time"].replace('Z', '+00:00')),
                    severity_id=anomalous_log.get("severity_id", 0),
                    message=anomalous_log.get("message", ""),
                    src_ip=anomalous_log.get("src_ip"),
                    dst_ip=anomalous_log.get("dst_ip"),
                    user=anomalous_log.get("user")
                )
            ]
            
            # Generate summary
            summary = self._generate_alert_summary(anomalous_log, anomaly_score, category)
            
            # Create alert object
            alert = Alert(
                alert_id=alert_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
                anomaly_score=anomaly_score,
                detection_algorithm=algorithm.upper(),
                threshold=threshold,
                severity=severity,
                status=AlertStatus.NEW,
                category=category,
                affected_entities=affected_entities,
                context_logs=context_logs,
                detection_window_start=start_time,
                detection_window_end=end_time,
                features=features,
                summary=summary,
                description=f"Anomaly detected with score {anomaly_score:.3f} using {algorithm.upper()}"
            )
            
            # Store alert in Elasticsearch
            alert_dict = alert.model_dump(mode='json')
            await es_service.store_alert(alert_dict)
            
            logger.info(f"Created alert {alert_id} with score {anomaly_score:.3f}")
            
            return alert_dict
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            return None
    
    def _generate_alert_summary(self, log: Dict[str, Any], score: float, category: str) -> str:
        """Generate human-readable alert summary"""
        if category == "auth_anomaly":
            user = log.get("user", "unknown")
            return f"Unusual authentication activity detected for user '{user}' (score: {score:.2f})"
        elif category == "network_anomaly":
            src_ip = log.get("src_ip", "unknown")
            dst_ip = log.get("dst_ip", "unknown")
            return f"Unusual network activity from {src_ip} to {dst_ip} (score: {score:.2f})"
        else:
            return f"Anomalous behavior detected (score: {score:.2f})"


# Singleton instance
detection_service = DetectionService()
