-- O2 Divers: إعداد قاعدة البيانات على Supabase
-- شغّل هذا الملف كاملاً مرة واحدة من: SQL Editor
-- مهم: غيّر 'CHANGE-ME' في الأسفل لكلمة مرور المشرف قبل التشغيل

create extension if not exists pgcrypto with schema extensions;

-- ===== الجداول (مقفلة: لا أحد يقرأها مباشرة من المتصفح) =====
create table if not exists public.members (
  n text primary key check (n ~ '^\d{4,6}$'),
  name text not null,
  pin_hash text not null,
  plan text not null default 'عادية',
  phone text not null check (phone ~ '^\d{10}$'),
  joined date not null default current_date,
  points int not null default 0 check (points >= 0),
  active boolean not null default true
);
create table if not exists public.app_settings (k text primary key, v text not null);
create table if not exists public.attempts (
  k text primary key, fails int not null default 0, locked_until timestamptz
);
alter table public.members enable row level security;
alter table public.app_settings enable row level security;
alter table public.attempts enable row level security;
-- بدون سياسات (policies) = لا وصول مباشر. الوصول فقط عبر الدوال أدناه.

-- ===== كلمة مرور المشرف (غيّرها) =====
insert into public.app_settings (k, v)
values ('admin_hash', extensions.crypt('admin123', extensions.gen_salt('bf')))
on conflict (k) do update set v = excluded.v;

-- ===== دوال مساعدة داخلية (غير متاحة من المتصفح) =====
create or replace function public._locked(p_key text) returns boolean
language sql security definer set search_path = public as $$
  select coalesce((select locked_until > now() from attempts where k = p_key), false)
$$;

create or replace function public._fail(p_key text) returns void
language plpgsql security definer set search_path = public as $$
declare f int;
begin
  insert into attempts (k, fails) values (p_key, 1)
  on conflict (k) do update set fails = attempts.fails + 1
  returning fails into f;
  if f >= 5 then
    update attempts set fails = 0, locked_until = now() + interval '10 minutes' where k = p_key;
  end if;
end $$;

create or replace function public._clear(p_key text) returns void
language sql security definer set search_path = public as $$
  delete from attempts where k = p_key
$$;

create or replace function public._admin_err(p_pw text) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  if _locked('admin') then
    return json_build_object('ok', false, 'error', 'محاولات كثيرة، حاول بعد 10 دقائق');
  end if;
  if exists (select 1 from app_settings where k = 'admin_hash' and v = crypt(coalesce(p_pw, ''), v)) then
    perform _clear('admin');
    return null;
  end if;
  perform _fail('admin');
  return json_build_object('ok', false, 'error', 'كلمة المرور غير صحيحة');
end $$;

-- ===== دخول العضو: يرجع بياناته فقط، بدون الرقم السري =====
create or replace function public.member_login(p_n text, p_pin text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare m members; k text := 'm_' || coalesce(p_n, '');
begin
  if _locked(k) then
    return json_build_object('ok', false, 'error', 'محاولات كثيرة، حاول بعد 10 دقائق');
  end if;
  select * into m from members where n = p_n and pin_hash = crypt(coalesce(p_pin, ''), pin_hash);
  if not found then
    perform _fail(k);
    return json_build_object('ok', false, 'error', 'رقم العضوية أو الرقم السري غير صحيح');
  end if;
  perform _clear(k);
  return json_build_object('ok', true, 'member', json_build_object(
    'n', m.n, 'name', m.name, 'plan', m.plan, 'phone', m.phone,
    'joined', m.joined::text, 'points', m.points, 'active', m.active));
end $$;

-- ===== عمليات المشرف =====
create or replace function public.admin_list(p_pw text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare e json;
begin
  e := _admin_err(p_pw);
  if e is not null then return e; end if;
  return json_build_object('ok', true, 'members', coalesce((
    select json_agg(json_build_object('n', n, 'name', name, 'plan', plan, 'phone', phone,
      'joined', joined::text, 'points', points, 'active', active) order by n)
    from members), '[]'::json));
end $$;

create or replace function public.admin_save(p_pw text, p_member jsonb, p_orig text default null) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare
  e json;
  v_n text := p_member->>'n';
  v_pin text := coalesce(p_member->>'pin', '');
  v_target text := coalesce(p_orig, p_member->>'n');
begin
  e := _admin_err(p_pw);
  if e is not null then return e; end if;

  if v_n !~ '^\d{4,6}$' or coalesce(p_member->>'name', '') = ''
     or (p_member->>'phone') !~ '^\d{10}$' or (p_member->>'points')::int < 0
     or (v_pin <> '' and v_pin !~ '^\d{4}$') then
    return json_build_object('ok', false, 'error', 'بيانات غير صالحة');
  end if;

  if exists (select 1 from members where n = v_target) then
    if v_n <> v_target and exists (select 1 from members where n = v_n) then
      return json_build_object('ok', false, 'error', 'رقم العضوية مستخدم');
    end if;
    update members set
      n = v_n, name = p_member->>'name', plan = p_member->>'plan', phone = p_member->>'phone',
      joined = (p_member->>'joined')::date, points = (p_member->>'points')::int,
      active = (p_member->>'active')::boolean,
      pin_hash = case when v_pin <> '' then crypt(v_pin, gen_salt('bf')) else pin_hash end
    where n = v_target;
  else
    if v_pin = '' then
      return json_build_object('ok', false, 'error', 'الرقم السري مطلوب للعضو الجديد');
    end if;
    if exists (select 1 from members where n = v_n) then
      return json_build_object('ok', false, 'error', 'رقم العضوية مستخدم');
    end if;
    insert into members (n, name, pin_hash, plan, phone, joined, points, active)
    values (v_n, p_member->>'name', crypt(v_pin, gen_salt('bf')), p_member->>'plan', p_member->>'phone',
      (p_member->>'joined')::date, (p_member->>'points')::int, (p_member->>'active')::boolean);
  end if;
  return json_build_object('ok', true);
exception when others then
  return json_build_object('ok', false, 'error', 'بيانات غير صالحة');
end $$;

create or replace function public.admin_delete(p_pw text, p_n text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare e json;
begin
  e := _admin_err(p_pw);
  if e is not null then return e; end if;
  delete from members where n = p_n;
  return json_build_object('ok', true);
end $$;

-- ===== الصلاحيات: المتصفح يستدعي الدوال الأربع فقط =====
revoke execute on function public._locked(text), public._fail(text), public._clear(text), public._admin_err(text)
  from public, anon, authenticated;
revoke execute on function public.member_login(text, text), public.admin_list(text),
  public.admin_save(text, jsonb, text), public.admin_delete(text, text) from public;
grant execute on function public.member_login(text, text), public.admin_list(text),
  public.admin_save(text, jsonb, text), public.admin_delete(text, text) to anon;

-- ===== عضو تجريبي (احذفه لاحقاً من لوحة المشرف) =====
insert into public.members (n, name, pin_hash, plan, phone, joined, points, active)
values ('0001', 'أحمد العتيبي', extensions.crypt('1234', extensions.gen_salt('bf')),
        'ذهبية', '0501234567', '2025-01-10', 1200, true)
on conflict (n) do nothing;
