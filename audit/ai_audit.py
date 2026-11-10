"""عقل التدقيق الذكي — يحوّل النتائج الخام إلى تفسير + كود إصلاح آمن.

يدعم ثلاث خدمات مجانية (أي واحد يكفي) ويعمل بسلام إن لم يوجد أي منها:
    GEMINI_API_KEY     → Google AI Studio
    GROQ_API_KEY       → Groq free tier
    OPENROUTER_API_KEY → OpenRouter
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Any

from .static_scan import ScanResult

PROMPT_HEADER = (
    "You are a senior application security engineer. Given static-analysis "
    "findings from the free tool 'Audit-Skill-ZeroBaran', explain each one in "
    "Arabic (concise, developer-friendly) and provide a safe replacement code "
    "snippet. Return STRICT JSON only, no prose:\n"
    '{"analyses":[{"rule_id":"...","explain":"سبب المشكلة والخطر بلغة عربية '
    'بسيطة في سطرين","fix_code":"كود إصلاح آمن جاهز للاستبدال"}]}\n'
    "If a finding needs no code change, set fix_code to an empty string.\n\n"
)


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 60) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _build_prompt(result: ScanResult, limit: int) -> str:
    lines = [PROMPT_HEADER]
    for i, f in enumerate(result.findings[:limit], 1):
        lines.append(
            f"{i}. rule_id={f.rule_id} severity={f.severity} "
            f"file={f.file}:{f.line}\n   title={f.title}\n   excerpt: {f.excerpt}"
        )
    return "\n".join(lines)


def _extract_json(text: str) -> dict:
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.MULTILINE).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start == -1 or end == -1:
        raise ValueError("no json object in model output")
    return json.loads(text[start:end + 1])


def _call_gemini(prompt: str) -> str:
    key = os.environ["GEMINI_API_KEY"]
    model = os.environ.get("GEMINI_MODEL", "gemini-2.0-flash")
    url = (f"https://generativelanguage.googleapis.com/v1beta/models/"
           f"{model}:generateContent?key={key}")
    data = _post_json(url, {"contents": [{"parts": [{"text": prompt}]}]}, {})
    return data["candidates"][0]["content"]["parts"][0]["text"]


def _call_openai_compatible(prompt: str, kind: str) -> str:
    if kind == "groq":
        base = "https://api.groq.com/openai/v1"
        key = os.environ["GROQ_API_KEY"]
        model = os.environ.get("GROQ_MODEL", "openai/gpt-oss-120b")
    else:
        base = "https://openrouter.ai/api/v1"
        key = os.environ["OPENROUTER_API_KEY"]
        model = os.environ.get("OPENROUTER_MODEL", "openai/gpt-4o-mini")
    data = _post_json(
        f"{base}/chat/completions",
        {"model": model, "messages": [{"role": "user", "content": prompt}],
         "temperature": 0.2, "max_tokens": 4000},
        {"Authorization": f"Bearer {key}"},
    )
    return data["choices"][0]["message"]["content"]


def available_provider() -> str | None:
    for env in ("GEMINI_API_KEY", "GROQ_API_KEY", "OPENROUTER_API_KEY"):
        if os.environ.get(env):
            return env
    return None


def analyze(result: ScanResult, limit: int | None = None) -> dict[str, Any]:
    """يُرجع {rule_id: {"explain", "fix_code"}} — فارغ إن لم توجد خدمة متاحة."""
    provider = available_provider()
    if not provider or not result.findings:
        return {}
    limit = limit or int(os.environ.get("AUDIT_MAX_AI_FINDINGS", "20"))
    prompt = _build_prompt(result, limit)
    try:
        if provider == "GEMINI_API_KEY":
            raw = _call_gemini(prompt)
        elif provider == "GROQ_API_KEY":
            raw = _call_openai_compatible(prompt, "groq")
        else:
            raw = _call_openai_compatible(prompt, "openrouter")
        data = _extract_json(raw)
        analyses = data.get("analyses") or data.get("results") or []
        return {
            str(a.get("rule_id")): {
                "explain": str(a.get("explain", "")).strip(),
                "fix_code": str(a.get("fix_code", "")).strip(),
            }
            for a in analyses if isinstance(a, dict) and a.get("rule_id")
        }
    except (urllib.error.URLError, KeyError, ValueError, IndexError, json.JSONDecodeError) as exc:
        return {"_error": {"explain": f"تعذّر الاتصال بخدمة الذكاء الاصطناعي: {exc}", "fix_code": ""}}
