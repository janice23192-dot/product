"""Redis cache layer implementation.

Provides caching for query results, deduplication, session data,
and general-purpose caching with TTL policies. Req 14.1-14.12.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

import redis.asyncio as redis


class RedisCache:
    """Redis cache client with key naming conventions and TTL policies."""

    # TTL policies for different data types
    TTL_POLICIES = {
        "query_result": timedelta(minutes=5),
        "session": timedelta(hours=8),
        "dedup": timedelta(seconds=60),
        "rate_limit": timedelta(minutes=1),
        "geolocation": timedelta(hours=24),
        "reputation": timedelta(hours=6),
        "config": timedelta(hours=1),
        "entity": timedelta(minutes=30),
        "ioc": timedelta(hours=12),
    }

    def __init__(self, redis_url: str) -> None:
        self.client = redis.from_url(redis_url, decode_responses=True)

    @staticmethod
    def _key(namespace: str, key: str) -> str:
        """Generate a namespaced cache key."""
        return f"sip:{namespace}:{key}"

    async def get(self, namespace: str, key: str) -> Any | None:
        """Get a cached value."""
        raw = await self.client.get(self._key(namespace, key))
        if raw is None:
            return None
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw

    async def set(
        self, namespace: str, key: str, value: Any, ttl: timedelta | None = None
    ) -> None:
        """Set a cached value with optional TTL."""
        if ttl is None:
            ttl = self.TTL_POLICIES.get(namespace, timedelta(minutes=15))
        serialized = json.dumps(value, default=str) if not isinstance(value, str) else value
        await self.client.set(self._key(namespace, key), serialized, ex=int(ttl.total_seconds()))

    async def delete(self, namespace: str, key: str) -> None:
        """Delete a cached value."""
        await self.client.delete(self._key(namespace, key))

    async def exists(self, namespace: str, key: str) -> bool:
        """Check if a key exists."""
        return bool(await self.client.exists(self._key(namespace, key)))

    async def increment(self, namespace: str, key: str, amount: int = 1) -> int:
        """Increment a counter."""
        full_key = self._key(namespace, key)
        result = await self.client.incr(full_key, amount)
        if result == amount:
            ttl = self.TTL_POLICIES.get(namespace, timedelta(minutes=15))
            await self.client.expire(full_key, int(ttl.total_seconds()))
        return result

    async def get_counter(self, namespace: str, key: str) -> int:
        """Get a counter value."""
        val = await self.client.get(self._key(namespace, key))
        return int(val) if val else 0

    async def add_to_set(self, namespace: str, key: str, *values: str) -> None:
        """Add values to a set."""
        await self.client.sadd(self._key(namespace, key), *values)

    async def is_in_set(self, namespace: str, key: str, value: str) -> bool:
        """Check set membership."""
        return bool(await self.client.sismember(self._key(namespace, key), value))

    async def publish(self, channel: str, message: Any) -> None:
        """Publish a message to a Redis channel."""
        serialized = json.dumps(message, default=str) if not isinstance(message, str) else message
        await self.client.publish(f"sip:{channel}", serialized)

    async def close(self) -> None:
        """Close the Redis connection."""
        await self.client.close()

    async def ping(self) -> bool:
        """Health check."""
        try:
            return await self.client.ping()
        except Exception:
            return False
