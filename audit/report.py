"""عرض نتائج التدقيق: نصّ ملوّن / JSON / Markdown."""

from __future__ import annotations

import json
import sys
import time
from dataclasses import asdict

from .static_scan import ScanResult

SEV_COLOR = {
    "critical": "\033[91m",  # أحمر
    "high": "\033[95m",      # أرجواني
    "medium": "\033[93m",    # أصفر
    "low": "\033[96m",       # سماوي
    "info": "\033[90m",      # رمادي
}
RESET = "\033[0m"
SEV_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}

# رموز قابلة للنسخ حتى مع دعم RTL في الطرفية
SEV_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO"}


def _color(sev: str, text: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{SEV_COLOR.get(sev, '')}{text}{RESET}"


def render_text(result: ScanResult, ai: dict | None = None, use_color: bool | None = None) -> str:
    use_color = sys.stdout.isatty() if use_color is None else use_color
    c = result.counts()
    lines = [
        "=" * 62,
        "  Audit-Skill-ZeroBaran  |  تقرير التدقيق الأمني",
        "=" * 62,
        f"  الملفات المفحوصة: {result.scanned_files}   الأسطر: {result.scanned_lines}",
        f"  النتيجة: {_color(result.worst, result.worst.upper(), use_color)}",
        "",
        f"  🔴 حرج: {c['critical']}    🟠 عالي: {c['high']}    "
        f"🟡 متوسط: {c['medium']}    🔵 منخفض: {c['low']}    ⚪ معلومات: {c['info']}",
        "-" * 62,
    ]
    if not result.findings:
        lines.append("  ✅ لم تُكتشف أي ثغرة — النظام نظيف.")
    for f in result.findings:
        head = f"[{SEV_LABEL.get(f.severity, 'INFO')}] {f.rule_id}"
        lines.append("")
        lines.append(_color(f.severity, head, use_color))
        lines.append(f"  العنوان : {f.title}")
        lines.append(f"  الموقع  : {f.file}:{f.line}")
        lines.append(f"  السبب   : {f.reason}")
        lines.append(f"  الإصلاح : {f.fix}")
        if f.excerpt:
            lines.append(f"  الكود   : {f.excerpt}")
        if ai and f.rule_id in ai:
            lines.append(f"  🤖 الذكاء: {ai[f.rule_id].get('explain', '')}")
            if ai[f.rule_id].get("fix_code"):
                lines.append("  🛠️ كود الإصلاح المقترح:")
                for ln in ai[f.rule_id]["fix_code"].splitlines()[:20]:
                    lines.append(f"      {ln}")
    if result.errors:
        lines.append("")
        lines.append("  ملاحظات: " + " | ".join(result.errors))
    lines.append("=" * 62)
    return "\n".join(lines)


def render_markdown(result: ScanResult, ai: dict | None = None) -> str:
    c = result.counts()
    lines = [
        "# 🛡️ Audit-Skill-ZeroBaran — تقرير التدقيق",
        "",
        f"- **التاريخ:** {time.strftime('%Y-%m-%d %H:%M UTC+00', time.gmtime())}",
        f"- **الملفات المفحوصة:** {result.scanned_files} | **الأسطر:** {result.scanned_lines}",
        f"- **النتيجة:** `{result.worst.upper()}`",
        "",
        "| 🔴 حرج | 🟠 عالي | 🟡 متوسط | 🔵 منخفض | ⚪ معلومات |",
        "|---|---|---|---|---|",
        f"| {c['critical']} | {c['high']} | {c['medium']} | {c['low']} | {c['info']} |",
        "",
    ]
    if not result.findings:
        lines.append("✅ **لم تُكتشف أي ثغرة.**")
    for f in result.findings:
        lines += [
            f"### `{SEV_LABEL.get(f.severity, 'INFO')}` {f.rule_id}",
            "",
            f"- **الموقع:** `{f.file}:{f.line}`",
            f"- **المشكلة:** {f.title}",
            f"- **السبب:** {f.reason}",
            f"- **الإصلاح:** {f.fix}",
        ]
        if f.excerpt:
            lines += ["", "```", f.excerpt, "```"]
        if ai and f.rule_id in ai:
            lines.append(f"- **تحليل الذكاء الاصطناعي:** {ai[f.rule_id].get('explain', '')}")
            if ai[f.rule_id].get("fix_code"):
                lines += ["", "```python", ai[f.rule_id]["fix_code"], "```"]
        lines.append("")
    return "\n".join(lines)


def render_json(result: ScanResult, ai: dict | None = None) -> str:
    payload = {
        "tool": "Audit-Skill-ZeroBaran",
        "version": "1.0.0",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "summary": {**result.counts(), "files": result.scanned_files,
                    "lines": result.scanned_lines, "verdict": result.worst},
        "findings": [asdict(f) for f in result.findings],
        "ai_analyses": ai or {},
        "errors": result.errors,
    }
    return json.dumps(payload, ensure_ascii=False, indent=2)
