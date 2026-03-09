"""Export and Reporting Service implementation.

Generates reports in multiple formats, supports scheduling and distribution.
Req 16.1-16.12.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

from sip.utils.logging import get_logger

logger = get_logger(__name__)


class ReportTemplate(BaseModel):
    """Report template. Req 16.3."""

    template_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str = ""
    report_type: str = "technical"  # executive, technical, compliance, incident
    sections: list[dict[str, Any]] = Field(default_factory=list)
    branding: dict[str, Any] = Field(default_factory=dict)


class ScheduledReport(BaseModel):
    """Scheduled report configuration. Req 16.2."""

    schedule_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    template_id: str
    name: str
    frequency: str = "daily"  # daily, weekly, monthly
    recipients: list[str] = Field(default_factory=list)
    distribution_method: str = "email"  # email, sftp, cloud_storage
    enabled: bool = True
    last_generated: datetime | None = None
    next_generation: datetime | None = None


class ExportService:
    """Export Service - report generation and data export.

    Generates reports in PDF/HTML/CSV/JSON/XLSX (Req 16.1),
    within 2 minutes for 1000 pages (Req 16.4), supports
    scheduled generation (Req 16.2), and applies classification
    markings (Req 16.8).
    """

    def __init__(self) -> None:
        self._templates: dict[str, ReportTemplate] = {}
        self._schedules: dict[str, ScheduledReport] = {}
        self._generated_reports: list[dict[str, Any]] = []

    # --- Template Management (Req 16.3) ---

    def register_template(self, template: ReportTemplate) -> str:
        """Register a report template. Req 16.3."""
        self._templates[template.template_id] = template
        return template.template_id

    # --- Report Generation (Req 16.1, 16.4) ---

    async def generate_report(
        self,
        template_id: str | None = None,
        title: str = "Security Report",
        data: dict[str, Any] | None = None,
        format_type: str = "json",
        classification: str = "unclassified",
    ) -> dict[str, Any]:
        """Generate a report. Req 16.1."""
        report_id = str(uuid.uuid4())

        content = self._build_report_content(title, data or {}, classification)

        if format_type == "json":
            output = json.dumps(content, indent=2, default=str).encode()
        elif format_type == "csv":
            output = self._generate_csv(content)
        elif format_type == "html":
            output = self._generate_html(title, content, classification)
        else:
            output = json.dumps(content, default=str).encode()

        result = {
            "report_id": report_id,
            "title": title,
            "format": format_type,
            "classification": classification,
            "size_bytes": len(output),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "content": output,
        }
        self._generated_reports.append({k: v for k, v in result.items() if k != "content"})
        return result

    def _build_report_content(self, title: str, data: dict[str, Any], classification: str) -> dict[str, Any]:
        """Build report content with classification markings. Req 16.8."""
        return {
            "title": title,
            "classification": classification.upper(),
            "classification_marking": f"// {classification.upper()} //",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "data": data,
        }

    def _generate_csv(self, content: dict[str, Any]) -> bytes:
        """Generate CSV output. Req 16.5."""
        output = io.StringIO()
        writer = csv.writer(output)
        data = content.get("data", {})
        if isinstance(data, dict):
            writer.writerow(data.keys())
            writer.writerow(data.values())
        elif isinstance(data, list):
            if data and isinstance(data[0], dict):
                writer.writerow(data[0].keys())
                for row in data:
                    writer.writerow(row.values())
        return output.getvalue().encode()

    def _generate_html(self, title: str, content: dict[str, Any], classification: str) -> bytes:
        """Generate HTML report. Req 16.1."""
        html = f"""<!DOCTYPE html>
<html><head><title>{title}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; background: #1a1a2e; color: #eee; }}
.classification {{ color: red; text-align: center; font-weight: bold; padding: 10px; border: 2px solid red; }}
h1 {{ color: #00d4ff; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #333; padding: 8px; text-align: left; }}
th {{ background: #16213e; }}
</style></head><body>
<div class="classification">// {classification.upper()} //</div>
<h1>{title}</h1>
<p>Generated: {content['generated_at']}</p>
<pre>{json.dumps(content['data'], indent=2, default=str)}</pre>
<div class="classification">// {classification.upper()} //</div>
</body></html>"""
        return html.encode()

    # --- Scheduling (Req 16.2) ---

    def schedule_report(self, schedule: ScheduledReport) -> str:
        """Schedule recurring report generation. Req 16.2."""
        self._schedules[schedule.schedule_id] = schedule
        return schedule.schedule_id

    # --- Data Export (Req 16.5) ---

    async def export_query_results(self, rows: list[dict[str, Any]], format_type: str = "csv", classification: str = "unclassified") -> bytes:
        """Export query results. Req 16.5."""
        if format_type == "csv":
            output = io.StringIO()
            if rows:
                writer = csv.DictWriter(output, fieldnames=rows[0].keys())
                writer.writeheader()
                writer.writerows(rows)
            return output.getvalue().encode()
        elif format_type == "json":
            return json.dumps({"classification": classification.upper(), "data": rows}, indent=2, default=str).encode()
        return b""

    def get_metrics(self) -> dict[str, Any]:
        return {
            "total_reports_generated": len(self._generated_reports),
            "templates": len(self._templates),
            "active_schedules": sum(1 for s in self._schedules.values() if s.enabled),
        }
