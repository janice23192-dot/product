"""Elasticsearch client for search indexing.

Manages index templates, mappings, and search operations.
Req 5.1-5.12.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class ElasticsearchClient:
    """Elasticsearch client wrapper for the platform.

    Provides index management, document indexing, and search
    operations optimized for security event data.
    """

    INDEX_TEMPLATES = {
        "security-events": {
            "index_patterns": ["sip-security-events-*"],
            "mappings": {
                "properties": {
                    "event_id": {"type": "keyword"},
                    "timestamp": {"type": "date"},
                    "source_id": {"type": "keyword"},
                    "event_type": {"type": "keyword"},
                    "severity": {"type": "integer"},
                    "classification": {"type": "keyword"},
                    "raw_data": {"type": "text"},
                    "attributes": {"type": "object", "dynamic": True},
                    "entities": {
                        "type": "nested",
                        "properties": {
                            "entity_id": {"type": "keyword"},
                            "entity_type": {"type": "keyword"},
                            "identifiers": {"type": "object"},
                        },
                    },
                    "tags": {"type": "keyword"},
                    "enrichments": {"type": "object", "dynamic": True},
                    "threat_indicators": {"type": "keyword"},
                    "geo_location": {"type": "geo_point"},
                    "risk_score": {"type": "float"},
                },
            },
            "settings": {
                "number_of_shards": 5,
                "number_of_replicas": 1,
                "refresh_interval": "10s",
            },
        },
        "alerts": {
            "index_patterns": ["sip-alerts-*"],
            "mappings": {
                "properties": {
                    "alert_id": {"type": "keyword"},
                    "detection_id": {"type": "keyword"},
                    "title": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    "description": {"type": "text"},
                    "severity": {"type": "integer"},
                    "confidence": {"type": "float"},
                    "status": {"type": "keyword"},
                    "assigned_to": {"type": "keyword"},
                    "mitre_tactics": {"type": "keyword"},
                    "mitre_techniques": {"type": "keyword"},
                    "created_at": {"type": "date"},
                },
            },
        },
        "audit-logs": {
            "index_patterns": ["sip-audit-*"],
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "user_id": {"type": "keyword"},
                    "action_type": {"type": "keyword"},
                    "resource_type": {"type": "keyword"},
                    "resource_id": {"type": "keyword"},
                    "outcome": {"type": "keyword"},
                    "details": {"type": "object", "dynamic": True},
                    "integrity_hash": {"type": "keyword"},
                },
            },
        },
    }

    def __init__(self, hosts: list[str], username: str = "", password: str = "", index_prefix: str = "sip") -> None:
        self.hosts = hosts
        self.username = username
        self.password = password
        self.index_prefix = index_prefix
        self._client: Any = None

    async def init(self) -> None:
        """Initialize Elasticsearch connection and create index templates."""
        from elasticsearch import AsyncElasticsearch

        auth = {}
        if self.username and self.password:
            auth = {"basic_auth": (self.username, self.password)}

        self._client = AsyncElasticsearch(hosts=self.hosts, **auth)

        for name, template in self.INDEX_TEMPLATES.items():
            try:
                await self._client.indices.put_index_template(
                    name=f"{self.index_prefix}-{name}",
                    body=template,
                )
            except Exception:
                pass  # Template may already exist

    async def index_document(self, index_name: str, document: dict[str, Any], doc_id: str | None = None) -> str:
        """Index a document."""
        full_index = f"{self.index_prefix}-{index_name}"
        result = await self._client.index(index=full_index, id=doc_id, body=document)
        return result["_id"]

    async def bulk_index(self, index_name: str, documents: list[dict[str, Any]]) -> dict[str, Any]:
        """Bulk index documents. Req 5.8."""
        full_index = f"{self.index_prefix}-{index_name}"
        actions = []
        for doc in documents:
            actions.append({"index": {"_index": full_index}})
            actions.append(doc)
        result = await self._client.bulk(body=actions)
        return result

    async def search(
        self,
        index_name: str,
        query: dict[str, Any],
        size: int = 100,
        from_: int = 0,
        sort: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Execute a search query. Req 5.2."""
        full_index = f"{self.index_prefix}-{index_name}"
        body: dict[str, Any] = {"query": query, "size": size, "from": from_}
        if sort:
            body["sort"] = sort
        result = await self._client.search(index=full_index, body=body)
        return {
            "hits": [hit["_source"] for hit in result["hits"]["hits"]],
            "total": result["hits"]["total"]["value"],
            "took_ms": result["took"],
        }

    async def full_text_search(self, index_name: str, text: str, fields: list[str] | None = None, size: int = 100) -> dict[str, Any]:
        """Full-text search across fields. Req 5.2."""
        query = {
            "multi_match": {
                "query": text,
                "fields": fields or ["*"],
                "type": "best_fields",
                "fuzziness": "AUTO",
            }
        }
        return await self.search(index_name, query, size=size)

    async def regex_search(self, index_name: str, field: str, pattern: str, size: int = 100) -> dict[str, Any]:
        """Regex pattern matching search. Req 5.3."""
        query = {"regexp": {field: {"value": pattern, "flags": "ALL"}}}
        return await self.search(index_name, query, size=size)

    async def close(self) -> None:
        """Close the Elasticsearch client."""
        if self._client:
            await self._client.close()

    async def ping(self) -> bool:
        """Health check."""
        try:
            return await self._client.ping()
        except Exception:
            return False
