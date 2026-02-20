"""PDF report renderer.

Converts a :class:`~aisec.core.models.ScanReport` to PDF via WeasyPrint.
WeasyPrint is an optional dependency; when it is not installed the renderer
falls back to generating an HTML file and logs a warning.
"""

from __future__ import annotations

import logging
from pathlib import Path

from aisec.core.models import ScanReport
from aisec.reports.renderers import html_renderer

logger = logging.getLogger(__name__)


def render(
    report: ScanReport,
    output_path: Path,
    template_dir: Path | None = None,
) -> Path:
    """Render a scan report to a PDF file.

    The function first renders the report to HTML using
    :func:`~aisec.reports.renderers.html_renderer.render`, then converts
    the HTML to PDF with WeasyPrint.

    If WeasyPrint is not installed, the renderer writes the HTML file
    instead and returns that path with a warning.

    Args:
        report: The complete scan report.
        output_path: Destination PDF file path.
        template_dir: Optional directory containing Jinja2 templates
            (forwarded to the HTML renderer).

    Returns:
        The resolved path to the written PDF (or HTML fallback) file.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Render HTML to a temporary sibling file
    html_path = output_path.with_suffix(".html")
    html_renderer.render(report, html_path, template_dir=template_dir)

    try:
        from weasyprint import HTML  # type: ignore[import-untyped]
    except ImportError:
        logger.warning(
            "WeasyPrint is not installed. Install it with "
            "'pip install weasyprint' for PDF support. "
            "Falling back to HTML output: %s",
            html_path,
        )
        return html_path.resolve()

    try:
        html_content = html_path.read_text(encoding="utf-8")
        HTML(string=html_content, base_url=str(html_path.parent)).write_pdf(
            str(output_path)
        )
        logger.info("PDF report written to %s", output_path)

        # Clean up intermediate HTML if PDF succeeded
        try:
            html_path.unlink()
        except OSError:
            pass

        return output_path.resolve()
    except Exception:
        logger.exception(
            "Failed to generate PDF; falling back to HTML output: %s",
            html_path,
        )
        return html_path.resolve()
