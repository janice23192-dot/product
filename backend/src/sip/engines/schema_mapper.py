"""Schema Mapper implementation.

Transforms source-specific data formats into the unified platform schema.
Supports JSON, XML, CSV, key-value, and unstructured log formats.
Req 28.1-28.12.
"""

from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sip.models.events import (
    ClassificationLevel,
    EntityType,
    NormalizedEntity,
    ParsedEvent,
)
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class ParsingRule:
    """A parsing rule for transforming raw data to platform schema. Req 28.7."""

    def __init__(
        self,
        name: str,
        source_type: str,
        format_type: str,  # json, xml, csv, kv, regex, grok
        pattern: str = "",
        field_mapping: dict[str, str] | None = None,
        timestamp_format: str = "",
        timestamp_field: str = "timestamp",
    ) -> None:
        self.name = name
        self.source_type = source_type
        self.format_type = format_type
        self.pattern = pattern
        self.field_mapping = field_mapping or {}
        self.timestamp_format = timestamp_format
        self.timestamp_field = timestamp_field
        self._compiled_pattern = re.compile(pattern) if pattern and format_type == "regex" else None


# Pre-built Grok-like patterns for common log formats
GROK_PATTERNS = {
    "SYSLOG": r"^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>\S+?)(?:\[(?P<pid>\d+)\])?\s*:\s*(?P<message>.+)$",
    "APACHE_ACCESS": r'^(?P<client_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\d+)',
    "NGINX_ACCESS": r'^(?P<client_ip>\S+)\s+-\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)\s+(?P<bytes>\d+)',
    "CEF": r"^CEF:\d+\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|(?P<version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extensions>.*)$",
    "WINDOWS_EVENT": r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})\s+(?P<event_id>\d+)\s+(?P<level>\w+)\s+(?P<source>\S+)\s+(?P<message>.+)$",
    "FIREWALL": r"^(?P<timestamp>\S+\s+\S+)\s+(?P<action>ALLOW|DENY|DROP)\s+(?P<protocol>\S+)\s+(?P<src_ip>\S+):(?P<src_port>\d+)\s+->\s+(?P<dst_ip>\S+):(?P<dst_port>\d+)",
    "JSON_LOG": r".*",  # Handled by JSON parser
    "KEY_VALUE": r"(\w+)=(\"[^\"]*\"|\S+)",
}

# Common timestamp formats
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%b %d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S %z",
    "%Y/%m/%d %H:%M:%S",
    "%m/%d/%Y %H:%M:%S",
]


class SchemaMapper:
    """Schema Mapper - transforms source data to platform schema.

    Supports parsing of JSON, XML, CSV, key-value, and unstructured
    log formats. Normalizes timestamps, entities, and validates
    against the platform schema. Req 28.1-28.12.
    """

    def __init__(self) -> None:
        self._parsing_rules: dict[str, list[ParsingRule]] = {}
        self._grok_patterns = GROK_PATTERNS
        self._quarantine: list[dict[str, Any]] = []

    # --- Parsing (Req 28.1, 28.2) ---

    async def parse(self, raw_data: bytes, source_type: str, source_id: str = "") -> ParsedEvent:
        """Parse raw data into a ParsedEvent. Req 28.1."""
        try:
            data_str = raw_data.decode("utf-8", errors="replace")
        except Exception:
            data_str = str(raw_data)

        # Try format-specific parsers
        parsed: dict[str, Any] = {}

        if self._looks_like_json(data_str):
            parsed = self._parse_json(data_str)
        elif self._looks_like_csv(data_str):
            parsed = self._parse_csv(data_str)
        elif self._looks_like_kv(data_str):
            parsed = self._parse_key_value(data_str)
        else:
            # Try regex patterns. Req 28.2
            parsed = self._parse_with_patterns(data_str, source_type)

        if not parsed:
            parsed = {"message": data_str, "event_type": "raw"}

        # Extract and normalize timestamp. Req 28.3
        timestamp = self._extract_timestamp(parsed)

        # Extract and normalize entities. Req 28.4, 28.5
        entities = self._extract_entities(parsed)

        # Build ParsedEvent
        event = ParsedEvent(
            event_id=str(uuid.uuid4()),
            timestamp=timestamp,
            source_id=source_id,
            event_type=parsed.get("event_type", source_type),
            severity=self._extract_severity(parsed),
            entities=entities,
            attributes=parsed,
            raw_data=raw_data,
            classification=ClassificationLevel.UNCLASSIFIED,
            tags={"source_type": source_type},
        )

        # Validate schema. Req 28.8
        validation = self.validate_schema(event)
        if not validation["valid"]:
            logger.warning("schema_validation_failed", errors=validation["errors"])
            self._quarantine.append({"event": event.model_dump(mode="json"), "errors": validation["errors"]})

        return event

    async def parse_batch(self, raw_data_list: list[bytes], source_type: str, source_id: str = "") -> list[ParsedEvent]:
        """Parse a batch of raw data. Req 28.10."""
        events = []
        for raw_data in raw_data_list:
            try:
                event = await self.parse(raw_data, source_type, source_id)
                events.append(event)
            except Exception as e:
                logger.error("batch_parse_error", error=str(e))
                self._quarantine.append({"raw_data": raw_data.hex(), "error": str(e)})
        return events

    # --- Schema Management ---

    def register_parsing_rule(self, source_type: str, rule: ParsingRule) -> None:
        """Register a custom parsing rule. Req 28.7."""
        if source_type not in self._parsing_rules:
            self._parsing_rules[source_type] = []
        self._parsing_rules[source_type].append(rule)

    def validate_schema(self, event: ParsedEvent) -> dict[str, Any]:
        """Validate a parsed event against the schema. Req 28.6, 28.8."""
        errors: list[str] = []

        if not event.event_id:
            errors.append("Missing event_id")
        if not event.timestamp:
            errors.append("Missing timestamp")
        if not event.source_id:
            errors.append("Missing source_id")
        if not event.event_type:
            errors.append("Missing event_type")

        return {"valid": len(errors) == 0, "errors": errors}

    # --- Timestamp Normalization (Req 28.3) ---

    @staticmethod
    def normalize_timestamp(timestamp_str: str, tz: str | None = None) -> datetime:
        """Parse and normalize timestamp to UTC. Req 28.3."""
        if not timestamp_str:
            return datetime.now(timezone.utc)

        # Try ISO format first
        try:
            dt = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        except (ValueError, TypeError):
            pass

        # Try common formats
        for fmt in TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(timestamp_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except (ValueError, TypeError):
                continue

        # Fallback to current time
        return datetime.now(timezone.utc)

    # --- Entity Normalization (Req 28.4, 28.5) ---

    @staticmethod
    def normalize_ip(ip_str: str) -> str:
        """Normalize IP address to canonical format. Req 28.4."""
        try:
            addr = ipaddress.ip_address(ip_str.strip())
            return str(addr)
        except ValueError:
            return ip_str.strip()

    @staticmethod
    def normalize_domain(domain_str: str) -> str:
        """Normalize domain name. Req 28.4."""
        domain = domain_str.strip().lower()
        if domain.startswith("www."):
            domain = domain[4:]
        domain = domain.rstrip(".")
        return domain

    @staticmethod
    def normalize_url(url_str: str) -> str:
        """Normalize URL. Req 28.4."""
        url_str = url_str.strip()
        if not url_str.startswith(("http://", "https://")):
            url_str = "https://" + url_str
        parsed = urlparse(url_str)
        return parsed.geturl()

    @staticmethod
    def normalize_email(email_str: str) -> str:
        """Normalize email address. Req 28.5."""
        return email_str.strip().lower()

    @staticmethod
    def normalize_user(user_str: str) -> str:
        """Normalize user identifier. Req 28.5."""
        user = user_str.strip()
        if "\\" in user:
            # domain\user format -> user@domain
            parts = user.split("\\", 1)
            return f"{parts[1]}@{parts[0]}".lower()
        return user.lower()

    # --- Pretty Printer (Req 28.11) ---

    @staticmethod
    def pretty_print(event: ParsedEvent) -> str:
        """Format normalized data back to human-readable. Req 28.11."""
        lines = [
            f"Event ID: {event.event_id}",
            f"Timestamp: {event.timestamp.isoformat()}",
            f"Source: {event.source_id}",
            f"Type: {event.event_type}",
            f"Severity: {event.severity}",
            f"Classification: {event.classification.value}",
        ]
        if event.entities:
            lines.append("Entities:")
            for entity in event.entities:
                lines.append(f"  - {entity.entity_type.value}: {entity.identifiers}")
        if event.attributes:
            lines.append("Attributes:")
            for key, value in sorted(event.attributes.items()):
                if key not in ("message",):
                    lines.append(f"  {key}: {value}")
        return "\n".join(lines)

    # --- Internal Parsers ---

    def _parse_json(self, data: str) -> dict[str, Any]:
        """Parse JSON format. Req 28.1."""
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}

    def _parse_csv(self, data: str) -> dict[str, Any]:
        """Parse CSV format. Req 28.1."""
        try:
            reader = csv.DictReader(io.StringIO(data))
            rows = list(reader)
            if rows:
                return dict(rows[0])
        except Exception:
            pass
        return {}

    def _parse_key_value(self, data: str) -> dict[str, Any]:
        """Parse key-value format. Req 28.1."""
        result: dict[str, Any] = {}
        pattern = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')
        for match in pattern.finditer(data):
            key = match.group(1)
            value = match.group(2) if match.group(2) is not None else match.group(3)
            result[key] = value
        return result

    def _parse_with_patterns(self, data: str, source_type: str) -> dict[str, Any]:
        """Parse using registered patterns and Grok patterns. Req 28.2."""
        # Try custom rules first
        if source_type in self._parsing_rules:
            for rule in self._parsing_rules[source_type]:
                if rule._compiled_pattern:
                    match = rule._compiled_pattern.match(data)
                    if match:
                        result = match.groupdict()
                        if rule.field_mapping:
                            result = {rule.field_mapping.get(k, k): v for k, v in result.items()}
                        return result

        # Try built-in Grok patterns
        for pattern_name, pattern in self._grok_patterns.items():
            try:
                match = re.match(pattern, data)
                if match:
                    result = match.groupdict()
                    result["_pattern"] = pattern_name
                    return result
            except re.error:
                continue

        return {}

    def _extract_timestamp(self, parsed: dict[str, Any]) -> datetime:
        """Extract and normalize timestamp from parsed data."""
        for field in ("timestamp", "@timestamp", "time", "datetime", "date", "eventTime", "created_at"):
            if field in parsed:
                val = parsed[field]
                if isinstance(val, datetime):
                    return val.astimezone(timezone.utc) if val.tzinfo else val.replace(tzinfo=timezone.utc)
                if isinstance(val, str):
                    return self.normalize_timestamp(val)
        return datetime.now(timezone.utc)

    def _extract_entities(self, parsed: dict[str, Any]) -> list[NormalizedEntity]:
        """Extract and normalize entities from parsed data. Req 28.4, 28.5."""
        entities: list[NormalizedEntity] = []
        ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
        email_pattern = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
        domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")

        flat_str = json.dumps(parsed) if isinstance(parsed, dict) else str(parsed)

        # Extract IPs
        seen_ips: set[str] = set()
        for ip_field in ("src_ip", "dst_ip", "client_ip", "server_ip", "ip", "source_ip", "dest_ip"):
            if ip_field in parsed:
                ip_val = self.normalize_ip(str(parsed[ip_field]))
                if ip_val and ip_val not in seen_ips:
                    seen_ips.add(ip_val)
                    entities.append(NormalizedEntity(
                        entity_type=EntityType.IP,
                        identifiers={"ip": ip_val},
                        attributes={"role": "source" if "src" in ip_field or "client" in ip_field else "target"},
                    ))

        # Extract from flat text if no structured IPs found
        if not seen_ips:
            for match in ip_pattern.finditer(flat_str):
                ip_val = self.normalize_ip(match.group())
                if ip_val not in seen_ips:
                    seen_ips.add(ip_val)
                    entities.append(NormalizedEntity(
                        entity_type=EntityType.IP,
                        identifiers={"ip": ip_val},
                    ))

        # Extract users
        for user_field in ("user", "username", "account", "actor", "src_user", "dst_user"):
            if user_field in parsed and parsed[user_field] and parsed[user_field] != "-":
                user_val = self.normalize_user(str(parsed[user_field]))
                entities.append(NormalizedEntity(
                    entity_type=EntityType.USER,
                    identifiers={"username": user_val},
                ))

        # Extract hostnames
        for host_field in ("hostname", "host", "computer_name", "device_name"):
            if host_field in parsed and parsed[host_field]:
                entities.append(NormalizedEntity(
                    entity_type=EntityType.HOST,
                    identifiers={"hostname": str(parsed[host_field]).lower()},
                ))

        # Extract domains from URLs
        if "url" in parsed:
            try:
                domain = urlparse(str(parsed["url"])).netloc
                if domain:
                    entities.append(NormalizedEntity(
                        entity_type=EntityType.DOMAIN,
                        identifiers={"domain": self.normalize_domain(domain)},
                    ))
            except Exception:
                pass

        # Extract file hashes. Req 24.2
        for hash_field in ("md5", "sha1", "sha256", "file_hash"):
            if hash_field in parsed and parsed[hash_field]:
                entities.append(NormalizedEntity(
                    entity_type=EntityType.FILE,
                    identifiers={hash_field: str(parsed[hash_field])},
                ))

        return entities

    def _extract_severity(self, parsed: dict[str, Any]) -> int:
        """Extract severity from parsed data."""
        for field in ("severity", "priority", "level", "risk_score"):
            if field in parsed:
                val = parsed[field]
                if isinstance(val, (int, float)):
                    return max(0, min(100, int(val)))
                if isinstance(val, str):
                    severity_map = {
                        "critical": 90, "high": 75, "medium": 50,
                        "low": 25, "info": 10, "informational": 10,
                        "emergency": 95, "alert": 85, "error": 70,
                        "warning": 50, "notice": 30, "debug": 5,
                    }
                    return severity_map.get(val.lower(), 50)
        return 0

    @staticmethod
    def _looks_like_json(data: str) -> bool:
        return data.strip().startswith(("{", "["))

    @staticmethod
    def _looks_like_csv(data: str) -> bool:
        lines = data.strip().split("\n")
        if len(lines) >= 2:
            first_line_commas = lines[0].count(",")
            return first_line_commas >= 2
        return False

    @staticmethod
    def _looks_like_kv(data: str) -> bool:
        return bool(re.search(r"\w+=\S+", data))
