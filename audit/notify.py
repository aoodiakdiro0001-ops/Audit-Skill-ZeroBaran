"""طبقة التنبيه الفوري — Telegram Bot (اختياري بالكامل)."""

from __future__ import annotations

import os
import urllib.error
import urllib.parse
import urllib.request

from .static_scan import ScanResult

SEV_ICON = {"critical": "🔴 حرج", "high": "🟠 عالي", "medium": "🟡 متوسط",
            "low": "🔵 منخفض", "info": "⚪ معلومات"}


def is_configured() -> bool:
    return bool(os.environ.get("TELEGRAM_BOT_TOKEN") and os.environ.get("TELEGRAM_CHAT_ID"))


def build_message(result: ScanResult, repo: str = "", ai: dict | None = None) -> str:
    c = result.counts()
    lines = [
        "🛡️ <b>Audit-Skill-ZeroBaran</b> — تنبيه أمني",
        f"📦 المستودع: <code>{repo or 'local'}</code>",
        f"🔍 الملفات: {result.scanned_files} | الأسطر: {result.scanned_lines}",
        f"النتيجة: <b>{result.worst.upper()}</b>",
        f"🔴 {c['critical']} | 🟠 {c['high']} | 🟡 {c['medium']} | 🔵 {c['low']}",
        "",
    ]
    for f in result.findings[:5]:  # أخطر خمس فقط حتى لا يمتلئ التنبيه
        lines += [
            f"<b>{SEV_ICON.get(f.severity, f.severity)}</b> — <code>{f.rule_id}</code>",
            f"📍 <code>{f.file}:{f.line}</code>",
            f"💻 السبب: {f.reason}",
            f"🛠️ الإصلاح: {f.fix}",
        ]
        if ai and f.rule_id in ai and ai[f.rule_id].get("explain"):
            lines.append(f"🤖 {ai[f.rule_id]['explain']}")
        lines.append("")
    if len(result.findings) > 5:
        lines.append(f"… و{len(result.findings) - 5} إيجاداً آخر في التقرير الكامل.")
    if not result.findings:
        lines.append("✅ لم تُكتشف أي ثغرة — بيئة نظيفة.")
    return "\n".join(lines)


def notify(result: ScanResult, repo: str = "", ai: dict | None = None) -> tuple[bool, str]:
    """يرسل التنبيه فقط عند وجود ثغرة حرجة/عالية (أو إن لم تكن هناك ثغرات إطلاقاً)."""
    if not is_configured():
        return False, "telegram-not-configured"
    if result.findings and result.worst not in {"critical", "high"}:
        return False, "no-critical-or-high"

    text = build_message(result, repo, ai)
    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true",
    }).encode("utf-8")
    req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True, "sent"
    except urllib.error.HTTPError as exc:
        return False, f"http {exc.code}: {exc.read().decode('utf-8', 'ignore')[:200]}"
    except urllib.error.URLError as exc:
        return False, f"network: {exc.reason}"
