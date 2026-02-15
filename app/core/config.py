from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application configuration settings loaded from environment variables."""
    
    # Application Settings
    app_name: str = "FastAPI Log Ingestion Service"
    app_version: str = "1.0.0"
    debug: bool = True
    
    # Server Configuration
    host: str = "0.0.0.0"
    port: int = 8000
    
    # Elasticsearch Configuration
    elasticsearch_host: str = "elasticsearch"
    elasticsearch_port: int = 9200
    elasticsearch_user: str = "elastic"
    elasticsearch_password: str = "changeme"
    elasticsearch_index: str = "security-logs"
    
    # Elasticsearch Connection URL
    @property
    def elasticsearch_url(self) -> str:
        """Construct Elasticsearch connection URL."""
        return f"http://{self.elasticsearch_host}:{self.elasticsearch_port}"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


# Singleton instance
settings = Settings()
