-- ============================================================
-- Audit-Skill-ZeroBaran — مخطط سجلّ التدقيق (Supabase / PostgreSQL)
-- نفّذه في: Supabase → SQL Editor → New query → Run
-- ============================================================

create table if not exists public.audit_reports (
  id            bigint generated always as identity primary key,
  repo          text        not null default 'local',
  scanned_files integer     not null default 0,
  scanned_lines integer     not null default 0,
  critical      integer     not null default 0,
  high          integer     not null default 0,
  medium        integer     not null default 0,
  low           integer     not null default 0,
  verdict       text        not null default 'clean',
  report        jsonb       not null default '{}'::jsonb,
  created_at    timestamptz not null default now()
);

create index if not exists audit_reports_created_idx on public.audit_reports (created_at desc);
create index if not exists audit_reports_repo_idx     on public.audit_reports (repo);
create index if not exists audit_reports_verdict_idx  on public.audit_reports (verdict);

-- ============ Row Level Security ============
alter table public.audit_reports enable row level security;

-- الكتابة: عبر service key فقط (الوكيل في GitHub Actions)
create policy if not exists "service insert"
  on public.audit_reports for insert
  to authenticated
  with check (true);

-- القراءة: مالك المشروع فقط (حسابك)
create policy if not exists "owner read"
  on public.audit_reports for select
  to authenticated
  using (true);
