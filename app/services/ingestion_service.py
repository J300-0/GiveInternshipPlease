from typing import List, Dict, Any
import logging
import uuid
from datetime import datetime

from app.models.log import BaseLog
from app.services.elasticsearch_service import es_service
from app.services.storage_service import storage_service

logger = logging.getLogger(__name__)


class IngestionService:
    """
    Service for handling log ingestion logic.
    Validates, enriches, and processes logs for indexing.
    """
    
    @staticmethod
    def enrich_log(log: BaseLog) -> Dict[str, Any]:
        """
        Enrich log data with additional metadata.
        
        Args:
            log: Pydantic log model
            
        Returns:
            Enriched log dictionary
        """
        log_dict = log.model_dump()
        
        # Add enrichment metadata
        if "metadata" not in log_dict:
            log_dict["metadata"] = {}
        
        log_dict["metadata"]["enriched_at"] = datetime.utcnow().isoformat()
        log_dict["metadata"]["source"] = "fastapi-ingestion"
        
        return log_dict
    
    @staticmethod
    async def process_and_index_logs(logs: List[BaseLog]) -> Dict[str, Any]:
        """
        Process and index logs to Elasticsearch AND save to files.
        This is the background task that runs after returning 202 Accepted.
        
        Args:
            logs: List of validated log models
            
        Returns:
            Processing result summary
        """
        try:
            # Enrich all logs
            enriched_logs = [IngestionService.enrich_log(log) for log in logs]
            
            # Try to index to Elasticsearch (optional)
            es_result = {"success": 0, "failed": 0}
            try:
                es_result = await es_service.bulk_index_logs(enriched_logs)
                logger.info(f"Elasticsearch: {es_result['success']} succeeded, {es_result['failed']} failed")
            except Exception as e:
                logger.warning(f"Elasticsearch indexing failed, continuing with file storage: {e}")
            
            # Always save to file storage for AI consumption
            try:
                # Load existing processed logs
                existing_data = storage_service.load_processed_logs()
                all_logs = existing_data.get("logs", []) + enriched_logs
                
                # Save updated logs
                storage_service.save_processed_logs(all_logs)
                logger.info(f"Saved {len(enriched_logs)} logs to file storage. Total: {len(all_logs)}")
            except Exception as e:
                logger.error(f"File storage failed: {e}")
            
            return {
                "status": "completed",
                "total": len(logs),
                "elasticsearch": es_result,
                "file_storage": {"saved": len(enriched_logs)}
            }
            
        except Exception as e:
            logger.error(f"Error processing logs: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "total": len(logs)
            }
    
    @staticmethod
    def generate_job_id() -> str:
        """Generate a unique job ID for tracking background tasks."""
        return str(uuid.uuid4())


# Singleton instance
ingestion_service = IngestionService()
