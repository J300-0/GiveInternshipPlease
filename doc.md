
#### `app/api/` - API Layer
Contains the API route definitions.

- **`v1/`**: Version 1 of the API.
  - Aggregates routers for `logs`, `alerts`, and `playbooks`.
  - Exposed via `/api/v1`.

#### `app/core/` - Core Configuration
- **`config.py`**: Handles application settings (environment variables, defaults) using Pydantic.

#### `app/models/` - Data Models
Defines the data structures used throughout the application, likely using Pydantic models.
- **`log.py`**: Log entry schema.
- **`alert.py`**: Alert schema & severity definitions.

#### `app/services/` - Business Logic
Contains the core functional logic, separated from the API layer.

- **`detection_service.py`**
  -  Statistical anomaly detection. Uses PyOD  library  to analyze logs and generate alerts for anomalies.
- **`elasticsearch_service.py`**
  - **Purpose**: Interaction with the Elasticsearch cluster.
  - **Logic**: Handles indexing logs, searching, and storing alerts.
- **`ingestion_service.py`**
 Processing incoming logs.
  
- **`storage_service.py`**
 Local file storage management.
  

### `elk/` - Elastic Stack Configuration
(external dir)

- `docker-compose.yml` - configuration files to spin up Elasticsearch, Logstash, and Kibana.
