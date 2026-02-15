from elasticsearch import AsyncElasticsearch
from typing import Optional, Dict, Any, List
import logging
from datetime import datetime

from app.core.config import settings

logger = logging.getLogger(__name__)


class ElasticsearchService:
    """
    Async Elasticsearch service for managing connections and operations.
    """
    
    def __init__(self):
        self.client: Optional[AsyncElasticsearch] = None
        self.index_name = settings.elasticsearch_index
    
    async def connect(self) -> None:
        """Establish connection to Elasticsearch."""
        try:
            self.client = AsyncElasticsearch(
                [settings.elasticsearch_url],
                basic_auth=(settings.elasticsearch_user, settings.elasticsearch_password),
                verify_certs=False,
                request_timeout=30
            )
            
            # Test connection
            if await self.client.ping():
                logger.info(f"Successfully connected to Elasticsearch at {settings.elasticsearch_url}")
            else:
                logger.error("Failed to ping Elasticsearch")
                raise ConnectionError("Cannot connect to Elasticsearch")
                
        except Exception as e:
            logger.error(f"Error connecting to Elasticsearch: {e}")
            raise
    
    async def disconnect(self) -> None:
        """Close Elasticsearch connection gracefully."""
        if self.client:
            await self.client.close()
            logger.info("Elasticsearch connection closed")
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Check Elasticsearch health status.
        
        Returns:
            Dict containing health status information
        """
        try:
            if not self.client:
                return {"status": "disconnected", "error": "Client not initialized"}
            
            health = await self.client.cluster.health()
            return {
                "status": "connected",
                "cluster_name": health.get("cluster_name"),
                "cluster_status": health.get("status"),
                "number_of_nodes": health.get("number_of_nodes")
            }
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def create_index(self) -> bool:
        """
        Create the logs index with proper mappings if it doesn't exist.
        
        Returns:
            True if index was created or already exists, False otherwise
        """
        try:
            # Check if index exists
            exists = await self.client.indices.exists(index=self.index_name)
            
            if exists:
                logger.info(f"Index '{self.index_name}' already exists")
                return True
            
            # Define index mappings for OCSF fields
            mappings = {
                "mappings": {
                    "properties": {
                        "time": {"type": "date"},
                        "severity_id": {"type": "integer"},
                        "category_uid": {"type": "integer"},
                        "class_uid": {"type": "integer"},
                        "activity_id": {"type": "integer"},
                        "type_uid": {"type": "integer"},
                        "message": {"type": "text"},
                        "status": {"type": "keyword"},
                        "metadata": {"type": "object", "enabled": True},
                        
                        # Network fields
                        "src_ip": {"type": "ip"},
                        "src_port": {"type": "integer"},
                        "dst_ip": {"type": "ip"},
                        "dst_port": {"type": "integer"},
                        "protocol": {"type": "keyword"},
                        "bytes_in": {"type": "long"},
                        "bytes_out": {"type": "long"},
                        
                        # Authentication fields
                        "user": {"type": "keyword"},
                        "user_uid": {"type": "keyword"},
                        "auth_protocol": {"type": "keyword"},
                        "logon_type": {"type": "keyword"},
                        "is_mfa": {"type": "boolean"},
                        "session_uid": {"type": "keyword"},
                        
                        # Ingestion metadata
                        "ingested_at": {"type": "date"}
                    }
                }
            }
            
            # Create index
            await self.client.indices.create(index=self.index_name, body=mappings)
            logger.info(f"Created index '{self.index_name}' with OCSF mappings")
            return True
            
        except Exception as e:
            logger.error(f"Error creating index: {e}")
            return False
    
    async def index_log(self, log_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Index a single log document.
        
        Args:
            log_data: Log data dictionary
            
        Returns:
            Elasticsearch response
        """
        try:
            # Add ingestion timestamp
            log_data["ingested_at"] = datetime.utcnow().isoformat()
            
            response = await self.client.index(
                index=self.index_name,
                document=log_data
            )
            
            logger.debug(f"Indexed log with ID: {response['_id']}")
            return response
            
        except Exception as e:
            logger.error(f"Error indexing log: {e}")
            raise
    
    async def bulk_index_logs(self, logs: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Bulk index multiple log documents.
        
        Args:
            logs: List of log data dictionaries
            
        Returns:
            Summary of bulk operation
        """
        try:
            from elasticsearch.helpers import async_bulk
            
            # Prepare bulk actions
            actions = []
            ingestion_time = datetime.utcnow().isoformat()
            
            for log in logs:
                log["ingested_at"] = ingestion_time
                actions.append({
                    "_index": self.index_name,
                    "_source": log
                })
            
            # Execute bulk operation
            success, failed = await async_bulk(
                self.client,
                actions,
                raise_on_error=False
            )
            
            logger.info(f"Bulk indexed {success} logs, {len(failed)} failed")
            
            return {
                "success": success,
                "failed": len(failed),
                "total": len(logs)
            }
            
        except Exception as e:
            logger.error(f"Error in bulk indexing: {e}")
            raise
    
    async def create_alerts_index(self) -> bool:
        """
        Create the alerts index with proper mappings if it doesn't exist.
        
        Returns:
            True if index was created or already exists, False otherwise
        """
        try:
            alerts_index = "security-alerts"
            
            # Check if index exists
            exists = await self.client.indices.exists(index=alerts_index)
            
            if exists:
                logger.info(f"Index '{alerts_index}' already exists")
                return True
            
            # Define index mappings for Alert schema
            mappings = {
                "mappings": {
                    "properties": {
                        "alert_id": {"type": "keyword"},
                        "created_at": {"type": "date"},
                        "updated_at": {"type": "date"},
                        "anomaly_score": {"type": "float"},
                        "detection_algorithm": {"type": "keyword"},
                        "threshold": {"type": "float"},
                        "severity": {"type": "integer"},
                        "status": {"type": "keyword"},
                        "category": {"type": "keyword"},
                        "affected_entities": {"type": "object", "enabled": True},
                        "context_logs": {"type": "nested"},
                        "detection_window_start": {"type": "date"},
                        "detection_window_end": {"type": "date"},
                        "features": {"type": "object", "enabled": True},
                        "summary": {"type": "text"},
                        "description": {"type": "text"},
                        "metadata": {"type": "object", "enabled": True}
                    }
                }
            }
            
            # Create index
            await self.client.indices.create(index=alerts_index, body=mappings)
            logger.info(f"Created index '{alerts_index}' with Alert mappings")
            return True
            
        except Exception as e:
            logger.error(f"Error creating alerts index: {e}")
            return False
    
    async def query_recent_logs(
        self,
        start_time: datetime,
        end_time: datetime,
        size: int = 1000
    ) -> List[Dict[str, Any]]:
        """
        Query logs within a time window for detection.
        
        Args:
            start_time: Start of time window
            end_time: End of time window
            size: Maximum number of logs to retrieve
            
        Returns:
            List of log documents
        """
        try:
            query = {
                "query": {
                    "range": {
                        "time": {
                            "gte": start_time.isoformat(),
                            "lte": end_time.isoformat()
                        }
                    }
                },
                "size": size,
                "sort": [{"time": "desc"}]
            }
            
            response = await self.client.search(index=self.index_name, body=query)
            
            logs = []
            for hit in response["hits"]["hits"]:
                log = hit["_source"]
                log["_id"] = hit["_id"]  # Include document ID
                logs.append(log)
            
            logger.info(f"Retrieved {len(logs)} logs from {start_time} to {end_time}")
            return logs
            
        except Exception as e:
            logger.error(f"Error querying recent logs: {e}")
            return []
    
    async def store_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Store an alert in the alerts index.
        
        Args:
            alert_data: Alert data dictionary
            
        Returns:
            Elasticsearch response
        """
        try:
            alerts_index = "security-alerts"
            
            # Ensure alerts index exists
            await self.create_alerts_index()
            
            response = await self.client.index(
                index=alerts_index,
                id=alert_data.get("alert_id"),
                document=alert_data
            )
            
            logger.info(f"Stored alert {alert_data.get('alert_id')} in {alerts_index}")
            return response
            
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            raise
    
    async def query_alerts(
        self,
        page: int = 1,
        page_size: int = 10,
        severity: Optional[int] = None,
        status: Optional[str] = None,
        category: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Query alerts with filtering and pagination.
        
        Args:
            page: Page number (1-indexed)
            page_size: Number of alerts per page
            severity: Filter by severity level
            status: Filter by status
            category: Filter by category
            
        Returns:
            Dictionary with alerts and pagination info
        """
        try:
            alerts_index = "security-alerts"
            
            # Build query filters
            filters = []
            if severity is not None:
                filters.append({"term": {"severity": severity}})
            if status:
                filters.append({"term": {"status": status}})
            if category:
                filters.append({"term": {"category": category}})
            
            query = {
                "query": {
                    "bool": {
                        "filter": filters
                    }
                } if filters else {"match_all": {}},
                "from": (page - 1) * page_size,
                "size": page_size,
                "sort": [{"created_at": "desc"}]
            }
            
            response = await self.client.search(index=alerts_index, body=query)
            
            alerts = [hit["_source"] for hit in response["hits"]["hits"]]
            total = response["hits"]["total"]["value"]
            
            logger.info(f"Retrieved {len(alerts)} alerts (page {page}, total {total})")
            
            return {
                "alerts": alerts,
                "total": total,
                "page": page,
                "page_size": page_size
            }
            
        except Exception as e:
            logger.error(f"Error querying alerts: {e}")
            return {
                "alerts": [],
                "total": 0,
                "page": page,
                "page_size": page_size
            }
    
    async def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific alert by ID.
        
        Args:
            alert_id: Alert identifier
            
        Returns:
            Alert document or None
        """
        try:
            alerts_index = "security-alerts"
            
            response = await self.client.get(index=alerts_index, id=alert_id)
            
            logger.info(f"Retrieved alert {alert_id}")
            return response["_source"]
            
        except Exception as e:
            logger.error(f"Error retrieving alert {alert_id}: {e}")
            return None


# Singleton instance
es_service = ElasticsearchService()
