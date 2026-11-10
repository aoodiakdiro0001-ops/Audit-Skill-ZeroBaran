"""واجهة سطر الأوامر: python -m audit scan <path> [خيارات]"""

from __future__ import annotations

import argparse
import os
import sys

from . import __version__
from .report import render_json, render_markdown, render_text
from .rules import severity_rank
from .static_scan import full_scan

SEV_ORDER = {"none": -1, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_dotenv(path: str = ".env") -> None:
    """قارئ .env بسيط بلا أي حزمة خارجية."""
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError:
        pass


def _profile_set(name: str) -> set[str]:
    if name == "all":
        return {"default", "skills", "identity"}
    return {name}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="audit",
        description="Audit-Skill-ZeroBaran — تدقيق أمني مجاني للمستودعات ومهارات الوكلاء.",
    )
    p.add_argument("--version", action="version", version=f"Audit-Skill-ZeroBaran {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="فحص مسار وإصدار تقرير")
    s.add_argument("path", nargs="?", default=".", help="المسار المراد فحصه (الافتراضي: .)")
    s.add_argument("--profile", choices=["all", "default", "skills", "identity"], default="all",
                   help=" مجموعة القواعد: all (الافتراضي) | default | skills | identity")
    s.add_argument("--format", choices=["text", "json", "md"], default="text")
    s.add_argument("--out", help="حفظ التقرير في ملف بدل/مع طباعة الشاشة")
    s.add_argument("--fail-on", choices=list(SEV_ORDER), default=None,
                   help="إرجاع رمز خروج 1 عند بلوغ هذه الخطورة (افتراضي: AUDIT_FAIL_ON أو none)")
    s.add_argument("--ai", action="store_true", help="تفعيل عقل التدقيق الذكي إن وُجد مفتاح")
    s.add_argument("--no-external", action="store_true",
                   help="تعطيل Semgrep/Bandit والاكتفاء بالمحرّك المدمج")
    s.add_argument("--no-store", action="store_true", help="عدم إرسال التقرير إلى Supabase")
    s.add_argument("--no-notify", action="store_true", help="عدم إرسال تنبيه Telegram")
    s.add_argument("--repo", default="", help="اسم المستودع المُسجَّل في السجل والتنبيه")
    s.add_argument("--owner", default="Baran Avisat")
    s.add_argument("--email", default="Baranavisat@gmail.com")
    s.add_argument("--phone", default="00905313263722")
    s.add_argument("--quiet", action="store_true", help="إظهار الملخص فقط")
    return p


def cmd_scan(args: argparse.Namespace) -> int:
    from .ai_audit import analyze
    from .notify import notify
    from .store import store_report

    target = args.path
    if not os.path.exists(target):
        print(f"error: path not found: {target}", file=sys.stderr)
        return 2

    result = full_scan(
        target,
        profiles=_profile_set(args.profile),
        external=not args.no_external,
    )

    ai: dict = {}
    if args.ai:
        ai = analyze(result)
        if "_error" in ai:
            result.errors.append(ai["_error"]["explain"])

    if args.format == "json":
        rendered = render_json(result, ai)
    elif args.format == "md":
        rendered = render_markdown(result, ai)
    else:
        rendered = render_text(result, ai, use_color=None if sys.stdout.isatty() else False)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        if args.format != "text":
            print(f"report written: {args.out}")
    if not args.out or args.format == "text":
        print(rendered)
    elif not args.quiet:
        print(rendered if args.format != "json" else f"json findings: {len(result.findings)}")

    repo = args.repo or os.path.basename(os.path.abspath(target))
    if not args.no_store:
        ok, msg = store_report(result, repo, ai)
        if ok:
            print(f"[store] supabase: {msg}")
    if not args.no_notify:
        ok, msg = notify(result, repo, ai)
        if ok:
            print(f"[notify] telegram: {msg}")

    fail_on = args.fail_on if args.fail_on is not None else os.environ.get("AUDIT_FAIL_ON", "none")
    threshold = SEV_ORDER.get(str(fail_on).lower(), -1)
    if threshold > 0:
        worst = max((severity_rank(f.severity) for f in result.findings), default=-1)
        if worst >= threshold:
            print(f"\n[FAIL] ثغرات تبلغ خطورة '{fail_on}' أو أعلى — كسر البناء.",
                  file=sys.stderr)
            return 1
    print(f"\n[OK] verdict={result.worst} findings={len(result.findings)}")
    return 0


def main(argv: list[str] | None = None) -> int:
    # ويندوز: تجنب انهيار الطباعة على ترميزات مثل cp1256
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    _load_dotenv()
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    try:
        return cmd_scan(args)
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
