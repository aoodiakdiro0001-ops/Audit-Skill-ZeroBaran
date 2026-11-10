"""طبقة الهوية والملكية — تدقيق مطابقة المستودع لهويتك المهنية.

يتحقق من: وجود LICENSE، ذكر المؤلف وبيانات الدعم الصحيحة، خلو المستودع من
ملفات `.env` مُยกَّاة (committed)، واكتمال بيانات الاتصال المطلوبة.
"""

from __future__ import annotations

import os
import re
import subprocess
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .static_scan import Finding

DEFAULT_OWNER = "Baran Avisat"
DEFAULT_EMAIL = "Baranavisat@gmail.com"
DEFAULT_PHONE = "00905313263722"


def _finding(rule_id, severity, title, reason, fix, file, line=0, excerpt="", group="identity"):
    from .static_scan import Finding
    return Finding(rule_id, severity, title, reason, fix, file, line, excerpt, group)


def _read(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return fh.read()
    except OSError:
        return ""


def run_identity_checks(root: str, owner: str = DEFAULT_OWNER,
                        email: str = DEFAULT_EMAIL, phone: str = DEFAULT_PHONE) -> list["Finding"]:
    out: list[Finding] = []
    root = os.path.abspath(root)

    license_path = next((p for p in ("LICENSE", "LICENSE.md", "LICENSE.txt")
                         if os.path.exists(os.path.join(root, p))), None)
    if not license_path:
        out.append(_finding(
            "identity.no-license", "medium",
            "لا يوجد ملف LICENSE",
            "المستودع بلا ترخيص = لا حقوق ملكية واضحة ولا استخدام مشروع مسموح.",
            "أضف ملف LICENSE (MIT) باسم المؤلف والسنة.",
            "LICENSE",
        ))

    readme_path = next((p for p in ("README.md", "README.MD", "readme.md", "README.txt")
                        if os.path.exists(os.path.join(root, p))), None)
    readme = _read(readme_path) if readme_path else ""
    if not readme:
        out.append(_finding(
            "identity.no-readme", "medium",
            "لا يوجد README",
            "غياب التوثيق يضعف الاحترافية ويمنع المبيعات والتبني.",
            "أضف README.md يشرح المشروع وطريقة التشغيل وبيانات المؤلف.",
            "README.md",
        ))
    else:
        if owner and owner.lower() not in readme.lower():
            out.append(_finding(
                "identity.missing-author", "low",
                f"اسم المؤلف غير مذكور في README ({owner})",
                "حفظ الملكية يتطلب ذكر المؤلف بوضوح في واجهة المستودع.",
                f"أضف سطر «المؤلف: {owner}» في قسم الملكية والدعم.",
                readme_path or "README.md",
            ))
        if email and email.lower() not in readme.lower():
            out.append(_finding(
                "identity.missing-email", "low",
                "بريد الدعم غير مذكور في README",
                "غياب قناة دعم يفقد المشروع مصداقية ويعرقل الإبلاغ عن الثغرات.",
                f"أضف: {email} في قسم بيانات الدعم.",
                readme_path or "README.md",
            ))
        if phone and phone not in readme.replace(" ", ""):
            out.append(_finding(
                "identity.missing-phone", "info",
                "رقم الواتساب غير مذكور في README",
                "قناة تواصل مباشرة ترفع ثقة العملاء في المنتج.",
                f"أضف رقم الواتساب {phone} قرب البريد في قسم الدعم.",
                readme_path or "README.md",
            ))

    # هل رُفع ملف أسرار إلى Git فعلاً؟
    try:
        proc = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                              cwd=root, capture_output=True, text=True, timeout=30)
        tracked = proc.stdout.split()
    except (OSError, subprocess.SubprocessError):
        tracked = []
    leaked = [f for f in tracked if os.path.basename(f) in {".env"} or
              (f.startswith(".env") and not f.endswith(".example"))]
    for f in sorted(set(leaked))[:20]:
        out.append(_finding(
            "identity.env-committed", "critical",
            "ملف أسرار داخل قائمة ملفات Git",
            f"الملف {f} مُصرَّح برفعه — أي مفتاح بداخله منشور علناً.",
            f"شغّل: git rm --cached {f} ثم أضف {f} إلى .gitignore وألغِ المفاتيح المتسرّبة.",
            f,
        ))
    return out
