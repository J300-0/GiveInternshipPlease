"""
Storage Service - Hybrid Elasticsearch + File-based
Reads from Elasticsearch, processes, outputs to JSON files for AI
"""

import json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class StorageService:
    """Manages data storage and retrieval"""
    
    def __init__(self, data_dir: str = "/app/data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        
        self.processed_logs_file = self.data_dir / "processed_logs.json"
        self.alerts_file = self.data_dir / "alerts.json"
        
    def save_processed_logs(self, logs: List[Dict[str, Any]]):
        """Save processed logs to JSON file for AI consumption"""
        try:
            with open(self.processed_logs_file, 'w') as f:
                json.dump({
                    "total": len(logs),
                    "generated_at": datetime.utcnow().isoformat(),
                    "logs": logs
                }, f, indent=2, default=str)
            logger.info(f"Saved {len(logs)} processed logs to {self.processed_logs_file}")
        except Exception as e:
            logger.error(f"Error saving processed logs: {e}")
            raise
    
    def save_alerts(self, alerts: List[Dict[str, Any]]):
        """Save alerts to JSON file for AI consumption"""
        try:
            with open(self.alerts_file, 'w') as f:
                json.dump({
                    "total": len(alerts),
                    "generated_at": datetime.utcnow().isoformat(),
                    "alerts": alerts
                }, f, indent=2, default=str)
            logger.info(f"Saved {len(alerts)} alerts to {self.alerts_file}")
        except Exception as e:
            logger.error(f"Error saving alerts: {e}")
            raise
    
    def load_processed_logs(self) -> Dict[str, Any]:
        """Load processed logs from file"""
        if self.processed_logs_file.exists():
            with open(self.processed_logs_file, 'r') as f:
                return json.load(f)
        return {"total": 0, "logs": []}
    
    def load_alerts(self) -> Dict[str, Any]:
        """Load alerts from file"""
        if self.alerts_file.exists():
            with open(self.alerts_file, 'r') as f:
                return json.load(f)
        return {"total": 0, "alerts": []}
    
    def append_alert(self, alert: Dict[str, Any]):
        """Append a single alert to the alerts file"""
        data = self.load_alerts()
        data["alerts"].append(alert)
        data["total"] = len(data["alerts"])
        data["generated_at"] = datetime.utcnow().isoformat()
        self.save_alerts(data["alerts"])


# Singleton instance
storage_service = StorageService()
