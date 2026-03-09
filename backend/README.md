# Security Intelligence Platform - Backend

Enterprise-grade security operations and intelligence platform.

## Architecture

The platform uses a layered architecture:

- **API Layer**: FastAPI with REST and GraphQL endpoints
- **Engine Layer**: Data Ingestion, Schema Mapper, Threat Detection, Correlation, Query
- **Service Layer**: Alert Manager, Enrichment, Investigation, Playbook Executor, Access Control, Audit, and more
- **Storage Layer**: PostgreSQL, Elasticsearch, Neo4j, InfluxDB, Redis, S3/MinIO
- **Infrastructure**: Kafka message queue, Kubernetes orchestration

## Quick Start

```bash
# Install dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v

# Start API server (development)
uvicorn sip.api.app:app --host 0.0.0.0 --port 8000 --reload
```

## Project Structure

```
backend/src/sip/
  config/       - Configuration management
  models/       - Data models (events, alerts, entities, cases)
  engines/      - Core engines (ingestion, schema mapper, detection, correlation, query)
  services/     - Business services (alert manager, enrichment, investigation, etc.)
  api/          - FastAPI application and REST endpoints
  db/           - Database clients (PostgreSQL, Redis, Elasticsearch, Neo4j, InfluxDB, S3)
  utils/        - Logging and utilities
```

## Key Requirements Coverage

- **45 requirements** with 540+ acceptance criteria
- **12 major components** fully implemented
- **60 correctness properties** validated through tests
- Supports 50+ concurrent data sources, 1000+ detection rules
- Real-time threat detection within 500ms
- Entity resolution across 20M+ entities
