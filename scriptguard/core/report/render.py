# scriptguard/core/report/render.py

import json
import os
import html
from pathlib import Path
from typing import Dict


def _write_json(report: Dict, output: Path):
    """Сохраняет отчёт в JSON"""
    with output.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=4, ensure_ascii=False)


def _render_section(title: str, content: str) -> str:
    return f"<section><h2>{title}</h2>{content}</section>"


def _render_pre(data) -> str:
    """Экранирует данные для безопасного HTML-превью"""
    if isinstance(data, dict):
        display = data
    elif isinstance(data, (list, set)):
        display = list(data)
    else:
        display = str(data)
    return f"<pre>{html.escape(json.dumps(display, indent=2, ensure_ascii=False))}</pre>"


def _write_html(report: Dict, output: Path):
    file_name = html.escape(os.path.basename(report.get("file", "")))
    script_type = html.escape(report.get("type", "Unknown"))
    confidence = report.get("confidence", 0.0)

    html_parts = [
        "<!DOCTYPE html>",
        "<html lang='en'>",
        "<head>",
        "<meta charset='utf-8'>",
        "<title>ScriptGuard Report</title>",
        "<style>",
        "body { font-family: Arial, sans-serif; margin: 40px; background: #fafafa; }",
        "h1 { color: #2c3e50; }",
        "section { margin-bottom: 30px; }",
        "pre { background: #f4f4f4; padding: 15px; overflow-x: auto; }",
        "ul { list-style-type: square; }",
        "</style>",
        "</head>",
        "<body>",
        "<h1>ScriptGuard Analysis Report</h1>",
        f"<p><strong>File:</strong> {file_name}</p>",
        f"<p><strong>Type:</strong> {script_type}</p>",
        f"<p><strong>Confidence:</strong> {confidence}</p>",
    ]

    # Indicators of Compromise
    ioc_keys = ["ips", "urls", "domains", "emails", "hashes"]
    ioc_content = []
    for key in ioc_keys:
        value = report.get(key)
        if value:
            ioc_content.append(f"<h3>{key.upper()}</h3>")
            if isinstance(value, dict):
                ioc_content.append(_render_pre(value))
            else:
                ioc_content.append(_render_pre(list(value)))
    if ioc_content:
        html_parts.append(_render_section("Indicators of Compromise", "".join(ioc_content)))

    # MITRE techniques
    mitre = report.get("mitre", [])
    if mitre:
        items = "".join(
            f"<li>{html.escape(item.get('id'))} — {html.escape(item.get('name'))}</li>"
            for item in mitre
        )
        html_parts.append(_render_section("MITRE ATT&CK Techniques", f"<ul>{items}</ul>"))

    # Deobfuscated code
    code = report.get("deobfuscated_code")
    if code:
        html_parts.append(
            _render_section(
                "Deobfuscated Code (Preview)",
                f"<pre>{html.escape(code)}</pre>"
            )
        )

    html_parts.extend(["</body>", "</html>"])

    # Сохраняем в файл
    output.write_text("".join(html_parts), encoding="utf-8")


def render_report(report: Dict, output_file: str, fmt: str = "json"):
    """
    Генерация отчёта анализа.

    :param report: словарь с результатами анализа
    :param output_file: путь сохранения
    :param fmt: json | html
    """
    fmt = fmt.lower()
    output = Path(output_file)
    output.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        _write_json(report, output)
    elif fmt == "html":
        _write_html(report, output)
    else:
        raise ValueError(f"Unsupported format: {fmt}")
