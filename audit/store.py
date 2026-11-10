"""طبقة الأرشيف — حفظ سجلّ التدقيق في Supabase (اختياري بالكامل).

يعطَّل تلقائياً إن لم يُضبط SUPABASE_URL أو SUPABASE_SERVICE_KEY.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request

from .static_scan import ScanResult

DEFAULT_TABLE = "audit_reports"


def is_configured() -> bool:
    return bool(os.environ.get("SUPABASE_URL") and os.environ.get("SUPABASE_SERVICE_KEY"))


def store_report(result: ScanResult, repo: str = "", ai: dict | None = None) -> tuple[bool, str]:
    if not is_configured():
        return False, "supabase-not-configured"

    url = os.environ["SUPABASE_URL"].rstrip("/")
    token = os.environ["SUPABASE_SERVICE_KEY"]
    table = os.environ.get("SUPABASE_TABLE", DEFAULT_TABLE)
    counts = result.counts()

    row = {
        "repo": repo or "local",
        "scanned_files": result.scanned_files,
        "scanned_lines": result.scanned_lines,
        "critical": counts["critical"],
        "high": counts["high"],
        "medium": counts["medium"],
        "low": counts["low"],
        "verdict": result.worst,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "report": json.dumps({
            "findings": [f.to_dict() for f in result.findings[:500]],
            "ai": ai or {},
        }, ensure_ascii=False),
    }

    req = urllib.request.Request(
        f"{url}/rest/v1/{table}",
        data=json.dumps(row).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "apikey": token,
            "Authorization": f"Bearer {token}",
            "Prefer": "return=minimal",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30):
            return True, "stored"
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "ignore")[:300]
        return False, f"http {exc.code}: {body}"
    except urllib.error.URLError as exc:
        return False, f"network: {exc.reason}"
