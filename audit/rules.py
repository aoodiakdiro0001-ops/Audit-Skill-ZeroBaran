"""قواعد الفحص الساكن المدمجة — تعمل بالكامل بدون إنترنت أو أي تثبيت.

كل قاعدة تحمل: المعرّف، الخطورة، عنوانها، سبب المشكلة، والإصلاح المقترح.
`profiles` تحدّد أي فلتر يستدعيها:
    default  → قواعد عامة لأي مستودع كود
    skills   → خصوص مهارات الوكلاء (SKILL.md / التعليمات)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # critical | high | medium | low | info
    title: str
    reason: str
    fix: str
    pattern: str
    profiles: tuple = ("default",)
    globs: tuple = ("*",)
    flags: int = 0  # extra re flags (0 = IGNORECASE مضافة دائماً)


RULES: list[Rule] = [
    # ---------------------------------------------------------------- مفاتيح
    Rule(
        "secret.github-pat", "critical",
        "GitHub Personal Access Token مكشوف في الكود",
        "أي شخص يملك هذا الرمز يملك صلاحية كاملة على مستودعاتك وحسابك.",
        "ألغِ المفتاح فوراً من GitHub → Settings → Developer settings، ثم انقله إلى متغيّر بيئة وأزله من سجل Git.",
        r"ghp_[A-Za-z0-9]{36}",
    ),
    Rule(
        "secret.github-fine", "critical",
        "GitHub fine-grained token مكشوف",
        "مفتاح GitHub دقيق الصلاحيات مكشوف داخل ملفات المستودع.",
        "ألغِ الرمز وأنشئ جديداً داخل GitHub Actions Secrets فقط.",
        r"github_pat_[A-Za-z0-9_]{50,}",
    ),
    Rule(
        "secret.openai-style", "critical",
        "مفتاح API بأسلوب sk- مكشوف",
        "مفتاح خدمة ذكاء اصطناعي مكشوف — يمكن استهلاك رصيدك أو سرقة بياناتك.",
        "انقله إلى متغيّر بيئة (أو GitHub Secrets) واحذفه من الكود ومن سجل Git.",
        r"\bsk-[A-Za-z0-9_\-]{20,}\b",
    ),
    Rule(
        "secret.openrouter", "critical",
        "مفتاح OpenRouter مكشوف",
        "مفتاح OpenRouter مكشوف داخل الشفرة.",
        "انقله إلى متغيّر بيئة وألغِه من لوحة OpenRouter إن نُشر علناً.",
        r"\bsk-or-v1-[A-Za-z0-9]{32,}\b",
    ),
    Rule(
        "secret.groq", "critical",
        "مفتاح Groq مكشوف",
        "مفتاح Groq مكشوف داخل الشفرة.",
        "انقله إلى متغيّر بيئة وألغِه من لوحة Groq إن نُشر علناً.",
        r"\bgsk_[A-Za-z0-9]{30,}\b",
    ),
    Rule(
        "secret.huggingface", "critical",
        "رمز HuggingFace مكشوف",
        "رمز HuggingFace مكشوف داخل الشفرة.",
        "انقله إلى متغيّر بيئة وألغِ الرمز من إعدادات الحساب.",
        r"\bhf_[A-Za-z0-9]{30,}\b",
    ),
    Rule(
        "secret.aws-key", "critical",
        "مفتاح AWS مكشوف",
        "مفتاح AWS يمنح صلاحية على بنية سحابية كاملة.",
        "انقله إلى متغيّر بيئة، احذفه من Git history، ودوّره من AWS IAM.",
        r"\bAKIA[0-9A-Z]{16}\b",
    ),
    Rule(
        "secret.private-key", "critical",
        "مفتاح خاص (Private Key) مضمّن في الكود",
        "ملفات المفاتيح الخاصة لا تُوضع في المستودعات أبداً.",
        "احذفها من المستودع ومن التاريخ، واستخدم متغيّر بيئة أو مدير أسرار.",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
    ),
    Rule(
        "secret.evm-private-key", "critical",
        "مفتاح خاص لمحفظة EVM (64 خانة) مكشوف",
        "هذا الرمز يمنح سيطرة كاملة على أموال المحفظة.",
        "أوقف نشره فوراً، احذفه من Git، وانقل أموالك إلى محفظة جديدة إن تسرّب علناً.",
        r"\b0x[a-fA-F0-9]{64}\b",
    ),
    Rule(
        "secret.generic-token", "high",
        "مفتاح/رمز مضمّن نصياً في المتغيّرات",
        "قيمة حسّاسة مكتوبة داخل الشفرة بدل متغيّر البيئة.",
        "استخدم os.environ / process.env بدل التضمين النصي.",
        r"(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*[\"'][A-Za-z0-9_\-\.]{24,}[\"']",
    ),
    # ---------------------------------------------------------------- حقن
    Rule(
        "sql.injection.fstring", "high",
        "استعلام SQL داخل f-string (خطر حقن)",
        "حقن SQL ممكن عبر أي مدخلات مستخدم تدخل الاستعلام مباشرة.",
        "استخدم استعلامات مُهيّأة (parameterized queries): cursor.execute('... WHERE id=?', (value,)).",
        r"(?i)\b(select|insert into|update|delete from)\b[^\"']{0,120}\{[a-z_][a-z0-9_\.]*\}",
    ),
    Rule(
        "sql.injection.concat", "high",
        "استعلام SQL مبنيّ بتوصيل نصوص (+ / %)",
        "توصيل نصوص مع SQL يفتح باب الحقن.",
        "مرّر القيم كمعاملات (parameters) فقط.",
        r"(?i)[\"']\s*\+\s*[a-z_][a-z0-9_\.]*\s*.*(select|insert into|update|delete from)\b",
    ),
    Rule(
        "cmd.injection-eval", "high",
        "تنفيذ كود ديناميكي (eval/exec)",
        "eval/exec يشغّل أي كود يصله من مدخلات غير موثوقة.",
        "استبدلها بتحليل بيانات آمن (json.loads / مخطط مُتحقَّق منه).",
        r"\b(eval|exec)\s*\(",
    ),
    Rule(
        "cmd.injection-shell", "high",
        "أوامر نظام بحقن محتمل (shell=True / os.system)",
        "تجميع مدخلات المستخدم مع أوامر النظام يسمح بتنفيذ أوامر اعتباطية.",
        "استخدم subprocess.run(list, shell=False) مع قائمة معاملات مُتحقَّق منها.",
        r"(?i)(os\.system\s*\(|subprocess\.(call|run|popen|check_output)\s*\([^)]*shell\s*=\s*True)",
    ),
    Rule(
        "cmd.pipe-to-shell", "critical",
        "تنزيل وتنفيذ مباشر (curl | bash)",  # audit:ignore
        "شفرة من مصدر خارجي تُشغَّل دون فحص — أشهر مسار اختراق.",
        "نزّل الملف، تحقّق من تجزئته (sha256)، افحصه، ثم نفّذه.",
        r"(?i)\b(curl|wget|iwr|invoke-webrequest)\b[^|\n]{0,140}\|\s*(sudo\s+)?(ba|z|fi)?sh\b",
    ),
    Rule(
        "xss.dom-write", "medium",
        "كتابة HTML ديناميكية (innerHTML / dangerouslySetInnerHTML)",  # audit:ignore
        "حقن XSS ممكن إن جاءت البيانات من مستخدم.",
        "استخدم textContent أو تهيئة صارمة (sanitize) قبل الحقن.",
        r"(?i)(\.innerhtml\s*=|dangerouslysetinnerhtml)",  # audit:ignore
    ),
    Rule(
        "crypto.weak-hash", "high",
        "تشفير ضعيف لكلمات المرور (MD5/SHA1)",
        "هذه الدوال سريعة الكسر لتخزين كلمات المرور.",
        "استخدم bcrypt / scrypt / Argon2 مع ملح عشوائي.",
        r"(?i)(password|passwd|pwd)[^.\n]{0,60}\b(md5|sha1)\b",
    ),
    Rule(
        "tls.verify-disabled", "medium",
        "تعطيل التحقق من شهادات TLS (verify=False)",  # audit:ignore
        "يفتح الباب لهجمات MITM على الاتصال.",
        "أصلح سلسلة الشهادات بدل تعطيل التحقق، أو حدّد CA موثوقاً.",
        r"(?i)\bverify\s*=\s*False\b",  # audit:ignore
    ),
    Rule(
        "deser.unsafe-pickle", "high",
        "فك تسلسل غير آمن (pickle/yaml.load)",
        "تحميل كائنات من بيانات غير موثوقة يسمح بتنفيذ كود.",
        "استخدم json، أو yaml.safe_load().",
        r"(?i)(pickle\.loads?\s*\(|yaml\.load\s*\([^)]*Loader\s*=\s*yaml\.(Unsafe|Full)Loader)",
    ),
    Rule(
        "path.traversal", "medium",
        "فتح ملف بمسار يحوي ../../../ (تسلل مسارات)",
        "مسار غير مُتحقَّق منه قد يقرأ ملفات خارج الدليل المسموح.",
        "تحقق من المسار النهائي بـ os.path.realpath وقارنه بالجذر المسموح.",
        r"(?i)open\s*\(\s*[\"'][^\"']*(\.\./|\\\\)[^\"']*[\"']",
    ),
    Rule(
        "net.plaintext-http", "low",
        "رابط HTTP غير مشفّر",
        "البيانات تسير نصاً وأي جهة على الشبكة تقرأها.",
        "استخدم HTTPS، واملأ روابط الخدمة بـ https://.",
        r"(?i)[\"']http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-z0-9\.\-]+",
    ),
    # ------------------------------------------------- مهارات الوكلاء
    Rule(
        "skill.ignore-instructions", "critical",
        "تعليم مهارة يلغي قواعد الوكيل السابقة",
        "نمط حقن سياق كلاسيكي: جعل الوكيل يتجاهل تعليماته الأمنية.",
        "احذف العبارة — أي مهارة صادقة لا تحتاج إلى إلغاء قواعد الوكيل.",
        r"(?i)\b(ignore|disregard|forget|override)\b[^.\n]{0,60}\b(previous|prior|above|earlier|system)\b[^.\n]{0,40}\b(instruction|rule|prompt|guideline)s?\b",
        profiles=("skills",),
        globs=("*.md", "*.mdx", "*.txt"),
    ),
    Rule(
        "skill.hidden-behavior", "high",
        "مهارة تخفي سلوكاً عن المستخدم",
        "أي مهارة تطلب إخفاء شيء عن المستخدم تخالف مبدأ الشفافية.",
        "اجعل السلوك معلناً وموثّقاً داخل المهارة نفسها.",
        r"(?i)\b(do not|don't|never|avoid)\b[^.\n]{0,40}\b(tell|inform|mention|reveal|show)\b[^.\n]{0,30}\b(user|human|owner)\b",
        profiles=("skills",),
        globs=("*.md", "*.mdx"),
    ),
    Rule(
        "skill.secret-exfil", "critical",
        "مهارة تطلب جمع/رفع مفاتيح أو ملفات حسّاسة",
        "توجيه الوكيل لالتقاط `.env` أو المفاتيح ثم رفعها = تسريب.",
        "احذف المسار كاملاً؛ المهارة يجب ألا تصل إلى ملفات الأسرار أصلاً.",
        r"(?i)\b(upload|send|post|exfiltrate|collect|read|grab|dump|open|access)\b[^;\n]{0,80}(?:\.env\b|api[_-]?keys?\b|secrets?\b|credentials?\b|private[_-]?keys?\b|wallet\b|\.git\b)",
        profiles=("skills",),
        globs=("*.md", "*.mdx"),
    ),
    Rule(
        "skill.hidden-exec", "critical",
        "مهارة تحوي تنفيذاً مخفياً (base64/IEX/powershell)",
        "تنفيذ مُقنَّع داخل التعليمات لا يُكشف للمراجعة.",
        "استبدل التنفيذ المخفي بأمر واضح مكتوب نصاً.",
        r"(?i)(base64\s+(-d|--decode)[^|\n]{0,40}\|\s*(ba|z)?sh)|(invoke-expression)|(iex\s*\()",  # audit:ignore
        profiles=("skills",),
        globs=("*.md", "*.mdx", "*.ps1", "*.sh"),
    ),
    Rule(
        "skill.reverse-shell", "critical",
        "قشرة عكسية (reverse shell) داخل ملف تعليمات",
        "أعلى درجات الخطورة: تمكين خارجي كامل للجهاز.",
        "احذف الملف فوراً وراجع مصدره ومن أضافه إلى المستودع.",
        r"(?i)(bash\s+-i\s+>&\s*/dev/tcp)|(nc\s+(-e|/dev/tcp))|(\bncat\b[^\n]{0,40}\-e)",
        profiles=("skills",),
        globs=("*",),
    ),
    Rule(
        "skill.remote-payload", "critical",
        "مهارة تسحب تنفيذاً من رابط خارجي",
        "محتوى خارجي يتغيّر بعد مراجعتك — تهديد مستمر (supply chain).",
        "ثبّت النسخة محلياً مع تجزئة موثّقة بدل تنفيذ محتوى حي.",
        r"(?i)\b(curl|wget|iwr|invoke-webrequest|downloadstring)\b[^\n]{0,120}https?://[^\s\"']+\s*(\|[^\n]{0,40}(sh|bash|powershell|iex))",
        profiles=("skills",),
        globs=("*.md", "*.mdx", "*.sh", "*.ps1"),
    ),
    # ------------------------------------------------------- نمط عام
    Rule(
        "debug.leftover", "low",
        "أدوات تصحيح متبقّدة في الإنتاج",
        " pdb/breakpoint توقف التنفيذ في الإنتاج.",
        "احذفها قبل الدفع إلى فرع الإنتاج.",
        r"(?i)(^|\n)\s*(import\s+pdb|breakpoint\s*\(\s*\))",
    ),
]


def rules_for(profiles: set[str] | list[str]) -> list[Rule]:
    """يُرجع القواعد التي تنتمي لأي من الملفّات المطلوبة."""
    wanted = set(profiles)
    return [r for r in RULES if wanted.intersection(r.profiles)]


def severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)
