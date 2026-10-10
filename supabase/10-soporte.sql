-- =============================================================================
-- LABS COMMAND CENTER 360™ · Sistema de Soporte y Tickets
-- Ejecutar DESPUÉS de 09-recursos.sql
--
-- Incidencias con dos niveles de escalado, apoyados en los roles de fábrica
-- que ya existen (no se añade ningún rol nuevo, no se toca rol_usuario):
--   Nivel 1 · Responsable de Soporte      -> rol 'manager'
--   Nivel 2 · Responsable del Responsable -> rol 'admin'
-- Un motor de reglas asigna en automático: toda incidencia de prioridad alta
-- o crítica se asigna sola, al abrirla, al Responsable de Soporte con menos
-- incidencias abiertas en ese momento; escalar a Nivel 2 hace lo mismo entre
-- los administradores. Nada se inventa: si no hay ningún manager o admin
-- activo, la incidencia queda sin asignar y lo dice el propio estado.
--
-- Regla de la casa: solo se crea. Nada de este archivo modifica una tabla,
-- política o función que no haya creado él mismo, salvo permisos_catalogo y
-- permisos_de_rol(), que están diseñados para crecer así desde el principio.
-- =============================================================================

-- =============================================================================
-- 1 · PERMISOS NUEVOS
-- =============================================================================
insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('soporte.ver',       'Soporte', 'Abrir y ver incidencias', 'Registrar incidencias propias y ver su estado', 400),
  ('soporte.gestionar', 'Soporte', 'Gestionar incidencias',   'Ver todas las incidencias, asignarlas y cambiar su estado', 410),
  ('soporte.escalar',   'Soporte', 'Escalar a Nivel 2',       'Derivar una incidencia al Responsable del Responsable', 420)
on conflict (clave) do update
  set grupo = excluded.grupo, nombre = excluded.nombre,
      descripcion = excluded.descripcion, orden = excluded.orden;

create or replace function public.permisos_de_rol(p_rol public.rol_usuario)
returns jsonb language sql stable as $$
  select coalesce(jsonb_object_agg(c.clave,
    case p_rol
      when 'admin' then true
      when 'manager' then c.clave in ('presu.ver','presu.crear','presu.dto','funnel.ver','exp.ver',
             'exp.estado','exp.hitos','exp.docs','hr.ver','hr.mover','hr.contratar',
             'com.llamadas','com.wsp','com.plant','sys.audit',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver','recursos.subir','recursos.borrar',
             'soporte.ver','soporte.gestionar','soporte.escalar')
      when 'commercial' then c.clave in ('presu.ver','presu.crear','funnel.ver','exp.ver','exp.docs',
             'com.llamadas','com.wsp',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs',
             'recursos.ver',
             'soporte.ver')
      when 'backoffice' then c.clave in ('exp.ver','exp.estado','exp.hitos','exp.docs','exp.borrar',
             'presu.ver','com.llamadas',
             'contactos.ver','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver',
             'soporte.ver')
    end), '{}'::jsonb)
  from public.permisos_catalogo c;
$$;

update public.perfiles
set permisos = permisos || jsonb_build_object(
  'soporte.ver',       true,
  'soporte.gestionar', rol in ('admin','manager'),
  'soporte.escalar',   rol in ('admin','manager')
)
where not (permisos ? 'soporte.ver');

-- =============================================================================
-- 2 · TABLAS
-- =============================================================================
create table if not exists public.tickets (
  id             bigserial primary key,
  titulo         text not null check (length(trim(titulo)) between 4 and 160),
  descripcion    text not null check (length(trim(descripcion)) >= 10),
  categoria      text not null default 'Plataforma' check (length(trim(categoria)) between 2 and 60),
  prioridad      text not null default 'media' check (prioridad in ('baja','media','alta','critica')),
  estado         text not null default 'abierto'
                   check (estado in ('abierto','en_progreso','escalado','resuelto','cerrado')),
  nivel_escalado smallint not null default 0 check (nivel_escalado in (0,1,2)),
  creado_por     uuid references public.perfiles(id) on delete set null,
  asignado_a     uuid references public.perfiles(id) on delete set null,
  creado         timestamptz not null default now(),
  actualizado    timestamptz not null default now()
);
create index if not exists tickets_estado_idx     on public.tickets(estado);
create index if not exists tickets_asignado_idx   on public.tickets(asignado_a);
create index if not exists tickets_creado_por_idx on public.tickets(creado_por);

drop trigger if exists tickets_actualizado on public.tickets;
create trigger tickets_actualizado before update on public.tickets
  for each row execute function public.marca_actualizado();

-- Historial de la incidencia: comentarios y cambios de estado. Solo se añade,
-- igual que la bitácora general — un histórico editable no serviría de nada.
create table if not exists public.ticket_eventos (
  id         bigserial primary key,
  ticket_id  bigint not null references public.tickets(id) on delete cascade,
  autor_id   uuid references public.perfiles(id) on delete set null,
  tipo       text not null default 'comentario' check (tipo in ('comentario','cambio_estado','escalado')),
  texto      text not null check (length(trim(texto)) > 0),
  creado     timestamptz not null default now()
);
create index if not exists ticket_eventos_idx on public.ticket_eventos(ticket_id, creado desc);

-- =============================================================================
-- 3 · MOTOR DE REGLAS · asignación automática y escalado
-- =============================================================================
-- Elige al responsable activo del rol dado con menos incidencias abiertas a
-- su cargo en este momento. Si no hay ninguno activo, no elige a nadie: la
-- incidencia queda sin asignar en vez de asignarse a alguien al azar.
create or replace function public.elige_responsable_ticket(p_rol public.rol_usuario)
returns uuid language sql stable security definer set search_path = public as $$
  select p.id
  from public.perfiles p
  where p.rol = p_rol and p.estado = 'Activo'
  order by (
    select count(*) from public.tickets t
    where t.asignado_a = p.id and t.estado not in ('resuelto','cerrado')
  ) asc, p.id asc
  limit 1;
$$;

create or replace function public.asigna_ticket_auto()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.prioridad in ('alta','critica') then
    new.nivel_escalado := greatest(new.nivel_escalado, 1);
    if new.asignado_a is null then
      new.asignado_a := public.elige_responsable_ticket('manager');
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists tickets_auto_asigna on public.tickets;
create trigger tickets_auto_asigna before insert on public.tickets
  for each row execute function public.asigna_ticket_auto();

-- Deja constancia sola de cada cambio de estado o de responsable, para que
-- el histórico nunca dependa de que alguien se acuerde de anotarlo.
create or replace function public.registra_cambio_ticket()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.estado is distinct from old.estado or new.asignado_a is distinct from old.asignado_a then
    insert into public.ticket_eventos(ticket_id, autor_id, tipo, texto)
    values (new.id, auth.uid(), 'cambio_estado',
      'Estado: ' || old.estado || ' → ' || new.estado ||
      case when new.asignado_a is distinct from old.asignado_a then ' · Reasignada' else '' end);
  end if;
  return new;
end;
$$;

drop trigger if exists tickets_registra_cambio on public.tickets;
create trigger tickets_registra_cambio after update on public.tickets
  for each row execute function public.registra_cambio_ticket();

-- Escalado a Nivel 2 (Responsable del Responsable). Solo quien tenga
-- soporte.escalar puede invocarla; SECURITY DEFINER porque quien escala no
-- tiene por qué tener permiso de UPDATE directo sobre la fila de otro.
create or replace function public.escala_ticket(p_id bigint)
returns void language plpgsql security definer set search_path = public as $$
declare
  v_resp uuid;
begin
  if not public.puedo('soporte.escalar') then
    raise exception 'No tienes permiso para escalar incidencias a Nivel 2.';
  end if;
  if not exists (select 1 from public.tickets where id = p_id) then
    raise exception 'La incidencia % no existe.', p_id;
  end if;

  v_resp := public.elige_responsable_ticket('admin');

  update public.tickets
    set nivel_escalado = 2, estado = 'escalado',
        asignado_a = coalesce(v_resp, asignado_a)
    where id = p_id;

  insert into public.ticket_eventos(ticket_id, autor_id, tipo, texto)
    values (p_id, auth.uid(), 'escalado', 'Escalada a Responsable del Responsable (Nivel 2).');
end;
$$;
revoke all on function public.escala_ticket(bigint) from public;
grant execute on function public.escala_ticket(bigint) to authenticated;

-- =============================================================================
-- 4 · RLS
-- =============================================================================
alter table public.tickets        enable row level security;
alter table public.ticket_eventos enable row level security;

drop policy if exists tickets_lee   on public.tickets;
drop policy if exists tickets_crea  on public.tickets;
drop policy if exists tickets_edita on public.tickets;

create policy tickets_lee on public.tickets
  for select using (
    public.puedo('soporte.gestionar')
    or creado_por = auth.uid()
    or asignado_a = auth.uid()
  );
create policy tickets_crea on public.tickets
  for insert with check (public.puedo('soporte.ver') and creado_por = auth.uid());
create policy tickets_edita on public.tickets
  for update using (public.puedo('soporte.gestionar'));
-- Sin política de DELETE: una incidencia no se borra, se cierra.

drop policy if exists ticket_eventos_lee  on public.ticket_eventos;
drop policy if exists ticket_eventos_crea on public.ticket_eventos;

create policy ticket_eventos_lee on public.ticket_eventos
  for select using (
    exists (
      select 1 from public.tickets t
      where t.id = ticket_eventos.ticket_id
        and (public.puedo('soporte.gestionar') or t.creado_por = auth.uid() or t.asignado_a = auth.uid())
    )
  );
create policy ticket_eventos_crea on public.ticket_eventos
  for insert with check (
    autor_id = auth.uid()
    and exists (
      select 1 from public.tickets t
      where t.id = ticket_eventos.ticket_id
        and (public.puedo('soporte.gestionar') or t.creado_por = auth.uid() or t.asignado_a = auth.uid())
    )
  );
-- Sin UPDATE ni DELETE: el histórico de una incidencia no se reescribe.

grant select, insert, update on public.tickets to authenticated;
grant select, insert on public.ticket_eventos to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from public.permisos_catalogo where clave like 'soporte.%') as permisos_nuevos,
  (select count(*) from pg_policies where schemaname='public'
     and tablename in ('tickets','ticket_eventos')) as politicas_tabla,
  (select count(*) from pg_trigger where tgrelid = 'public.tickets'::regclass and not tgisinternal) as triggers_tickets;
-- Esperado: permisos_nuevos = 3, politicas_tabla = 5, triggers_tickets = 3.
