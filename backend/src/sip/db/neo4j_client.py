"""Neo4j graph database client.

Manages entity nodes, relationships, and graph queries.
Req 3.1-3.10, 22.1-22.12.
"""

from __future__ import annotations

from typing import Any


class Neo4jClient:
    """Neo4j graph database client for entity relationship management."""

    # Node labels corresponding to entity types
    NODE_LABELS = ["User", "Host", "IPAddress", "Domain", "File", "Process", "Email", "Device", "Organization"]

    # Relationship types
    RELATIONSHIP_TYPES = [
        "CONNECTED_TO", "EXECUTED", "ACCESSED", "COMMUNICATED_WITH",
        "PARENT_OF", "AUTHENTICATED_AS", "RESOLVED_TO", "BELONGS_TO",
        "TRANSFERRED_TO", "OBSERVED_AT",
    ]

    def __init__(self, uri: str, username: str, password: str) -> None:
        self.uri = uri
        self.username = username
        self.password = password
        self._driver: Any = None

    async def init(self) -> None:
        """Initialize Neo4j connection and create indexes."""
        from neo4j import AsyncGraphDatabase

        self._driver = AsyncGraphDatabase.driver(self.uri, auth=(self.username, self.password))

        async with self._driver.session() as session:
            # Create indexes for entity lookups. Req 3.7
            for label in self.NODE_LABELS:
                try:
                    await session.run(f"CREATE INDEX IF NOT EXISTS FOR (n:{label}) ON (n.entity_id)")
                    await session.run(f"CREATE INDEX IF NOT EXISTS FOR (n:{label}) ON (n.canonical_id)")
                except Exception:
                    pass

    async def create_entity_node(self, entity_type: str, entity_id: str, properties: dict[str, Any]) -> None:
        """Create or update an entity node."""
        label = self._type_to_label(entity_type)
        query = f"""
        MERGE (n:{label} {{entity_id: $entity_id}})
        SET n += $properties
        SET n.updated_at = datetime()
        """
        async with self._driver.session() as session:
            await session.run(query, entity_id=entity_id, properties=properties)

    async def create_relationship(
        self,
        source_id: str,
        target_id: str,
        relationship_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        """Create or update a relationship between entities. Req 3.1."""
        query = f"""
        MATCH (a {{entity_id: $source_id}})
        MATCH (b {{entity_id: $target_id}})
        MERGE (a)-[r:{relationship_type}]->(b)
        SET r += $properties
        SET r.occurrence_count = COALESCE(r.occurrence_count, 0) + 1
        SET r.last_observed = datetime()
        """
        async with self._driver.session() as session:
            await session.run(
                query,
                source_id=source_id,
                target_id=target_id,
                properties=properties or {},
            )

    async def get_entity_relationships(self, entity_id: str, depth: int = 2) -> dict[str, Any]:
        """Get entity and its relationships up to specified depth. Req 3.1."""
        query = """
        MATCH path = (n {entity_id: $entity_id})-[*1..$depth]-(m)
        RETURN nodes(path) as nodes, relationships(path) as rels
        LIMIT 10000
        """
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        seen_nodes: set[str] = set()
        seen_edges: set[str] = set()

        async with self._driver.session() as session:
            result = await session.run(query, entity_id=entity_id, depth=depth)
            async for record in result:
                for node in record["nodes"]:
                    nid = dict(node).get("entity_id", "")
                    if nid and nid not in seen_nodes:
                        seen_nodes.add(nid)
                        nodes.append(dict(node))
                for rel in record["rels"]:
                    edge_key = f"{rel.start_node['entity_id']}-{rel.type}-{rel.end_node['entity_id']}"
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        edges.append({
                            "source": rel.start_node["entity_id"],
                            "target": rel.end_node["entity_id"],
                            "type": rel.type,
                            **dict(rel),
                        })

        return {"nodes": nodes, "edges": edges}

    async def resolve_entity(self, identifiers: dict[str, str]) -> str | None:
        """Find canonical entity ID from identifiers. Req 3.2."""
        conditions = " OR ".join(
            f"n.{key} = ${key.replace('.', '_')}" for key in identifiers
        )
        params = {key.replace(".", "_"): val for key, val in identifiers.items()}
        query = f"MATCH (n) WHERE {conditions} RETURN n.canonical_id AS canonical_id, n.entity_id AS entity_id LIMIT 1"

        async with self._driver.session() as session:
            result = await session.run(query, **params)
            record = await result.single()
            if record:
                return record["canonical_id"] or record["entity_id"]
        return None

    async def find_entity_clusters(self, min_connections: int = 3) -> list[list[str]]:
        """Find entity clusters based on connectivity. Req 3.9."""
        query = """
        CALL gds.wcc.stream({nodeProjection: '*', relationshipProjection: '*'})
        YIELD nodeId, componentId
        RETURN componentId, collect(gds.util.asNode(nodeId).entity_id) AS members
        HAVING size(members) >= $min_connections
        """
        clusters: list[list[str]] = []
        try:
            async with self._driver.session() as session:
                result = await session.run(query, min_connections=min_connections)
                async for record in result:
                    clusters.append(record["members"])
        except Exception:
            pass
        return clusters

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self._driver:
            await self._driver.close()

    async def ping(self) -> bool:
        """Health check."""
        try:
            async with self._driver.session() as session:
                await session.run("RETURN 1")
            return True
        except Exception:
            return False

    @staticmethod
    def _type_to_label(entity_type: str) -> str:
        """Convert entity type string to Neo4j node label."""
        mapping = {
            "user": "User", "host": "Host", "ip": "IPAddress",
            "domain": "Domain", "file": "File", "process": "Process",
            "email": "Email", "device": "Device", "organization": "Organization",
            "url": "Domain", "network_segment": "Host", "service_account": "User",
        }
        return mapping.get(entity_type.lower(), "Entity")
