-- =============================================================================
-- LABS COMMAND CENTER 360™ · Fichas de agente (área privada de cada agente)
-- Ejecutar DESPUÉS de 12-alta-agentes.sql. Se puede volver a ejecutar.
--
-- Cada agente (rol Gestión Comercial) tiene una ficha avanzada de gestión:
--   · agente_fichas       datos de gestión: zona, objetivos, plan de acción…
--   · agente_seguimiento  historial: notas, tareas, reuniones, evaluaciones…
--
-- Quién ve qué, decidido por la base de datos (RLS), no por la pantalla:
--   · Administrador: ve y gestiona la ficha de todos los agentes.
--   · Jefe de Equipo: hasta ejecutar 14-jefes-de-equipo.sql, la de todos; a
--     partir de ahí, solo la de los agentes que tiene asignados.
--   · Cada agente: ve SOLO la suya. Puede añadir sus propias notas y marcar
--     como hechas sus tareas, pero no cambia sus objetivos ni lo que escribe
--     dirección. Un agente nunca ve la ficha de otro.
-- Es la misma información para los dos lados: lo que escribe el jefe lo ve
-- el agente en «Mi ficha», y al revés.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1 · QUIÉN DIRIGE A CADA AGENTE
-- Aquí se crea con la regla básica (admin y cualquier jefe de equipo) SOLO si
-- no existe todavía: 14-jefes-de-equipo.sql la sustituye por la regla «solo
-- los agentes que tienes asignados», y volver a ejecutar este archivo no debe
-- deshacer eso.
-- -----------------------------------------------------------------------------
do $$
begin
  if to_regprocedure('public.dirijo_agente(uuid)') is null then
    execute $f$
      create function public.dirijo_agente(p_agente uuid)
      returns boolean language sql stable security definer set search_path = public as $b$
        select coalesce(public.mi_rol() in ('admin', 'manager'), false);
      $b$
    $f$;
  end if;
end $$;
revoke execute on function public.dirijo_agente(uuid) from public;
grant  execute on function public.dirijo_agente(uuid) to authenticated;

create or replace function public.es_agente(p_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfiles where id = p_id and rol = 'commercial');
$$;
revoke execute on function public.es_agente(uuid) from public;
grant  execute on function public.es_agente(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- 2 · TABLAS
-- -----------------------------------------------------------------------------
create table if not exists public.agente_fichas (
  agente_id        uuid primary key references public.perfiles(id) on delete cascade,
  zona             text not null default '' check (length(zona) <= 120),
  equipo           text not null default '' check (length(equipo) <= 120),
  especialidad     text not null default '' check (length(especialidad) <= 200),
  incorporacion    date,
  objetivo_mensual numeric(12,2) check (objetivo_mensual is null or objetivo_mensual >= 0),
  objetivos        text not null default '' check (length(objetivos) <= 4000),
  plan_accion      text not null default '' check (length(plan_accion) <= 4000),
  formacion        text not null default '' check (length(formacion) <= 4000),
  actualizado      timestamptz not null default now(),
  actualizado_por  uuid references public.perfiles(id) on delete set null
);
comment on table public.agente_fichas is
  'Ficha avanzada de gestión de cada agente. La ven el propio agente y su dirección.';

create table if not exists public.agente_seguimiento (
  id           bigint generated always as identity primary key,
  agente_id    uuid not null references public.perfiles(id) on delete cascade,
  autor_id     uuid references public.perfiles(id) on delete set null,
  autor_nombre text not null default '',
  tipo         text not null default 'nota'
               check (tipo in ('nota', 'tarea', 'objetivo', 'reunion', 'evaluacion')),
  titulo       text not null check (length(trim(titulo)) between 1 and 160),
  texto        text not null default '' check (length(texto) <= 4000),
  fecha        date,
  hecho        boolean not null default false,
  creado       timestamptz not null default now()
);
create index if not exists agente_seguimiento_agente_idx
  on public.agente_seguimiento(agente_id, creado desc);

-- -----------------------------------------------------------------------------
-- 3 · DISPARADORES
-- -----------------------------------------------------------------------------
-- La ficha apunta quién la tocó y cuándo, sin fiarse de lo que mande el panel.
create or replace function public.agente_ficha_sella()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not public.es_agente(new.agente_id) then
    raise exception 'Solo los agentes (Gestión Comercial) tienen ficha de agente.'
      using errcode = 'check_violation', hint = 'NO_ES_AGENTE';
  end if;
  new.actualizado     := now();
  new.actualizado_por := auth.uid();
  return new;
end $$;

drop trigger if exists agente_fichas_sella on public.agente_fichas;
create trigger agente_fichas_sella
  before insert or update on public.agente_fichas
  for each row execute function public.agente_ficha_sella();

-- En el seguimiento, el autor es siempre quien ha iniciado sesión, y el
-- agente solo puede cambiar la casilla «hecho» de lo que hay en su ficha.
create or replace function public.agente_seguimiento_guarda()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if not public.es_agente(new.agente_id) then
      raise exception 'Solo los agentes (Gestión Comercial) tienen ficha de agente.'
        using errcode = 'check_violation', hint = 'NO_ES_AGENTE';
    end if;
    if auth.uid() is not null then
      new.autor_id := auth.uid();
      select trim(nombre || ' ' || apellidos) into new.autor_nombre
        from public.perfiles where id = auth.uid();
    end if;
    new.creado := now();
    return new;
  end if;

  -- UPDATE
  if auth.uid() is not null and not public.dirijo_agente(old.agente_id) then
    if new.agente_id    is distinct from old.agente_id
       or new.autor_id     is distinct from old.autor_id
       or new.autor_nombre is distinct from old.autor_nombre
       or new.tipo         is distinct from old.tipo
       or new.titulo       is distinct from old.titulo
       or new.texto        is distinct from old.texto
       or new.fecha        is distinct from old.fecha
       or new.creado       is distinct from old.creado then
      raise exception 'Solo puedes marcar como hecha una tarea de tu ficha.'
        using errcode = 'insufficient_privilege', hint = 'SOLO_HECHO';
    end if;
  end if;
  new.agente_id := old.agente_id;
  new.autor_id  := old.autor_id;
  new.creado    := old.creado;
  return new;
end $$;

drop trigger if exists agente_seguimiento_guarda on public.agente_seguimiento;
create trigger agente_seguimiento_guarda
  before insert or update on public.agente_seguimiento
  for each row execute function public.agente_seguimiento_guarda();

-- -----------------------------------------------------------------------------
-- 4 · RLS
-- -----------------------------------------------------------------------------
alter table public.agente_fichas      enable row level security;
alter table public.agente_seguimiento enable row level security;

drop policy if exists agfichas_lee   on public.agente_fichas;
drop policy if exists agfichas_crea  on public.agente_fichas;
drop policy if exists agfichas_edita on public.agente_fichas;
drop policy if exists agfichas_borra on public.agente_fichas;

create policy agfichas_lee on public.agente_fichas
  for select using (public.dirijo_agente(agente_id) or agente_id = auth.uid());
create policy agfichas_crea on public.agente_fichas
  for insert with check (public.dirijo_agente(agente_id));
create policy agfichas_edita on public.agente_fichas
  for update using (public.dirijo_agente(agente_id)) with check (public.dirijo_agente(agente_id));
create policy agfichas_borra on public.agente_fichas
  for delete using (public.soy_admin());

drop policy if exists agseg_lee   on public.agente_seguimiento;
drop policy if exists agseg_crea  on public.agente_seguimiento;
drop policy if exists agseg_edita on public.agente_seguimiento;
drop policy if exists agseg_borra on public.agente_seguimiento;

create policy agseg_lee on public.agente_seguimiento
  for select using (public.dirijo_agente(agente_id) or agente_id = auth.uid());
-- Dirección escribe cualquier tipo; el agente, solo notas en su propia ficha.
create policy agseg_crea on public.agente_seguimiento
  for insert with check (
    public.dirijo_agente(agente_id) or (agente_id = auth.uid() and tipo = 'nota')
  );
create policy agseg_edita on public.agente_seguimiento
  for update using (public.dirijo_agente(agente_id) or agente_id = auth.uid())
  with check (public.dirijo_agente(agente_id) or agente_id = auth.uid());
-- Dirección borra cualquier apunte; el agente, solo las notas que escribió él.
create policy agseg_borra on public.agente_seguimiento
  for delete using (public.dirijo_agente(agente_id) or (agente_id = auth.uid() and autor_id = auth.uid()));

grant select, insert, update, delete on public.agente_fichas      to authenticated;
grant select, insert, update, delete on public.agente_seguimiento to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select
  (select count(*) from information_schema.tables where table_schema = 'public'
     and table_name in ('agente_fichas', 'agente_seguimiento'))              as tablas,
  (select count(*) from pg_policies where schemaname = 'public'
     and tablename in ('agente_fichas', 'agente_seguimiento'))               as politicas,
  (select count(*) from public.perfiles where rol = 'commercial')            as agentes;
-- Esperado: tablas = 2, politicas = 8, y en agentes cuántos tienes dados de alta.
