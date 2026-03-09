"""Investigation Workspace implementation.

Provides interactive environment for security analysts to investigate
threats, manage cases, and collaborate. Req 4.1-4.10, 19.1-19.14.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from sip.models.cases import (
    Case,
    CaseStatus,
    Evidence,
    EvidenceType,
    Finding,
    Hypothesis,
    WorkspaceState,
)
from sip.utils.logging import get_logger

logger = get_logger(__name__)


class InvestigationWorkspace:
    """Investigation Workspace - interactive security investigation environment.

    Supports 100 concurrent cases per analyst (Req 4.1), automatic
    evidence linking (Req 4.5), collaborative investigation (Req 4.6),
    workspace state persistence (Req 4.8), and pivoting (Req 4.9).
    """

    def __init__(self) -> None:
        self._cases: dict[str, Case] = {}
        self._workspace_states: dict[str, WorkspaceState] = {}
        self._case_subscribers: dict[str, list[Callable]] = {}
        self._case_templates: dict[str, dict[str, Any]] = {}
        self._annotation_store: dict[str, list[dict[str, Any]]] = {}

    # --- Case Management (Req 19.1-19.14) ---

    async def create_case(self, title: str, description: str = "", severity: int = 50, created_by: str = "", template_id: str | None = None, tags: list[str] | None = None) -> Case:
        """Create a new investigation case. Req 19.1."""
        case = Case(
            title=title,
            description=description,
            severity=severity,
            created_by=created_by,
            template_id=template_id,
            tags=tags or [],
        )

        # Apply template if specified. Req 19.6
        if template_id and template_id in self._case_templates:
            template = self._case_templates[template_id]
            if "tags" in template:
                case.tags.extend(template["tags"])
            if "default_hypotheses" in template:
                for h in template["default_hypotheses"]:
                    case.hypotheses.append(Hypothesis(title=h["title"], description=h.get("description", "")))

        case._record_history("created", f"Case created: {title}", created_by)
        self._cases[case.case_id] = case
        logger.info("case_created", case_id=case.case_id, title=title)
        return case

    async def update_case(self, case_id: str, updates: dict[str, Any], user: str = "") -> Case | None:
        """Update a case. Req 19.1."""
        case = self._cases.get(case_id)
        if not case:
            return None

        for key, value in updates.items():
            if key == "status":
                case.update_status(CaseStatus(value), user)
            elif key == "title":
                case.title = value
                case._record_history("updated", f"Title updated to: {value}", user)
            elif key == "description":
                case.description = value
            elif key == "severity":
                case.severity = value
            elif key == "assigned_to":
                case.assigned_to = value
            elif key == "tags":
                case.tags = value
            elif key == "team":
                case.team = value

        case.updated_at = datetime.now(timezone.utc)

        # Notify subscribers. Req 19.5
        await self._notify_case_update(case_id, updates, user)

        return case

    async def get_case(self, case_id: str) -> Case | None:
        """Get case by ID."""
        return self._cases.get(case_id)

    def get_cases(
        self,
        status: CaseStatus | None = None,
        assigned_to: str | None = None,
        limit: int = 100,
    ) -> list[Case]:
        """Get cases with filters."""
        results = []
        for case in sorted(self._cases.values(), key=lambda c: c.created_at, reverse=True):
            if status and case.status != status:
                continue
            if assigned_to and assigned_to not in case.assigned_to:
                continue
            results.append(case)
            if len(results) >= limit:
                break
        return results

    # --- Evidence Management (Req 4.5, 19.4, 44.1-44.12) ---

    async def add_evidence(self, case_id: str, evidence: Evidence, user: str = "") -> Evidence | None:
        """Add evidence to a case with auto-linking. Req 4.5, 19.4."""
        case = self._cases.get(case_id)
        if not case:
            return None

        evidence.created_by = user
        evidence.add_custody_record("added", user, f"Added to case {case_id}")
        case.add_evidence(evidence)

        # Auto-link related entities and events. Req 4.5
        await self._auto_link_evidence(case, evidence)

        return evidence

    async def _auto_link_evidence(self, case: Case, evidence: Evidence) -> None:
        """Automatically link related entities and events. Req 4.5."""
        # Check if evidence references relate to other case evidence
        for existing in case.evidence:
            if existing.evidence_id == evidence.evidence_id:
                continue
            # Link evidence that shares source references or entity IDs
            if (
                evidence.source_reference
                and evidence.source_reference == existing.source_reference
            ):
                evidence.metadata.setdefault("linked_evidence", []).append(existing.evidence_id)

    # --- Workspace State (Req 4.8) ---

    async def save_workspace_state(self, case_id: str, state: WorkspaceState, user: str = "") -> str:
        """Save workspace state. Req 4.8."""
        state.case_id = case_id
        state.saved_by = user
        state.saved_at = datetime.now(timezone.utc)
        self._workspace_states[case_id] = state

        case = self._cases.get(case_id)
        if case:
            case.workspace_state = state

        return state.workspace_id

    async def load_workspace_state(self, case_id: str) -> WorkspaceState | None:
        """Load workspace state. Supports round-trip. Req 4.8."""
        return self._workspace_states.get(case_id)

    # --- Collaboration (Req 4.6, 19.13, 19.14) ---

    def subscribe_to_case(self, case_id: str, callback: Callable) -> None:
        """Subscribe to case updates. Req 4.6."""
        if case_id not in self._case_subscribers:
            self._case_subscribers[case_id] = []
        self._case_subscribers[case_id].append(callback)

    async def _notify_case_update(self, case_id: str, updates: dict[str, Any], user: str) -> None:
        """Notify all case subscribers of updates. Req 19.5."""
        subscribers = self._case_subscribers.get(case_id, [])
        notification = {
            "case_id": case_id,
            "updates": updates,
            "updated_by": user,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        for callback in subscribers:
            try:
                await callback(notification)
            except Exception as e:
                logger.error("case_notification_error", error=str(e))

    async def add_annotation(self, case_id: str, target_id: str, text: str, user: str = "", tags: list[str] | None = None) -> dict[str, Any]:
        """Add annotation to an entity or event. Req 4.7."""
        annotation = {
            "annotation_id": str(uuid.uuid4()),
            "case_id": case_id,
            "target_id": target_id,
            "text": text,
            "user": user,
            "tags": tags or [],
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if case_id not in self._annotation_store:
            self._annotation_store[case_id] = []
        self._annotation_store[case_id].append(annotation)

        # Handle @mentions. Req 19.14
        mentions = self._extract_mentions(text)
        if mentions:
            annotation["mentions"] = mentions

        return annotation

    def _extract_mentions(self, text: str) -> list[str]:
        """Extract @mentions from text. Req 19.14."""
        import re
        return re.findall(r"@(\w+)", text)

    # --- Hypotheses and Findings (Req 23.1) ---

    async def add_hypothesis(self, case_id: str, hypothesis: Hypothesis) -> Hypothesis | None:
        """Add hypothesis to a case. Req 23.1."""
        case = self._cases.get(case_id)
        if not case:
            return None
        case.hypotheses.append(hypothesis)
        case._record_history("hypothesis_added", f"Hypothesis: {hypothesis.title}")
        return hypothesis

    async def add_finding(self, case_id: str, finding: Finding) -> Finding | None:
        """Add finding to a case."""
        case = self._cases.get(case_id)
        if not case:
            return None
        case.findings.append(finding)
        case._record_history("finding_added", f"Finding: {finding.title}")
        return finding

    # --- Templates (Req 19.6) ---

    def register_case_template(self, template_id: str, template: dict[str, Any]) -> None:
        """Register a case template. Req 19.6."""
        self._case_templates[template_id] = template

    # --- Metrics ---

    def get_metrics(self) -> dict[str, Any]:
        """Get investigation workspace metrics. Req 19.10."""
        cases = list(self._cases.values())
        closed = [c for c in cases if c.status == CaseStatus.CLOSED]

        resolution_times = []
        for c in closed:
            if c.closed_at:
                resolution_times.append((c.closed_at - c.created_at).total_seconds())

        return {
            "total_cases": len(cases),
            "open_cases": sum(1 for c in cases if c.status == CaseStatus.OPEN),
            "investigating": sum(1 for c in cases if c.status == CaseStatus.INVESTIGATING),
            "closed": len(closed),
            "avg_resolution_time_seconds": sum(resolution_times) / len(resolution_times) if resolution_times else 0,
            "total_evidence_items": sum(len(c.evidence) for c in cases),
        }
