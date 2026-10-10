-- =============================================================================
-- LABS COMMAND CENTER 360™ · Roles y permisos dinámicos
-- Ejecutar DESPUÉS de 07-contactos.sql
--
-- El sistema ya tenía permisos granulares por usuario (perfiles.permisos,
-- editables uno a uno en la ficha). Lo que faltaba: guardarlos como
-- PLANTILLAS con nombre, reutilizables y clonables, y controlar qué
-- pestañas del menú ve cada usuario — no solo qué puede hacer dentro de
-- ellas.
--
-- Diseño deliberado: una "plantilla" no crea un quinto nivel de acceso
-- paralelo a admin/manager/commercial/backoffice. Sigue apoyada en uno de
-- esos cuatro (columna basado_en), que es el nivel que ya usan las políticas
-- RLS de todo el esquema para decidir "veo lo mío" vs "lo veo todo". Lo que
-- la plantilla aporta es una variación de PERMISOS GRANULARES y de MÓDULOS
-- VISIBLES sobre ese nivel base — aplicar una plantilla escribe permisos y
-- modulos_visibles en la ficha del usuario, exactamente igual que ya hace
-- permisos_de_rol() al crear una cuenta. Convertir los cuatro niveles base
-- en roles arbitrarios de verdad exigiría reescribir cada política RLS que
-- hoy comprueba mi_rol() in (...), y eso es un cambio de arquitectura mucho
-- mayor que lo que se pidió aquí.
-- =============================================================================

-- =============================================================================
-- 1 · PERMISO NUEVO
-- =============================================================================
insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('roles.gestionar', 'Sistema', 'Gestionar roles personalizados', 'Crear, editar y aplicar plantillas de permisos', 165)
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
             'contactos.comentar','contactos.docs','contactos.borrar')
      when 'commercial' then c.clave in ('presu.ver','presu.crear','funnel.ver','exp.ver','exp.docs',
             'com.llamadas','com.wsp',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs')
      when 'backoffice' then c.clave in ('exp.ver','exp.estado','exp.hitos','exp.docs','exp.borrar',
             'presu.ver','com.llamadas',
             'contactos.ver','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar')
    end), '{}'::jsonb)
  from public.permisos_catalogo c;
$$;
-- roles.gestionar no entra en ningún rol base salvo admin (ya cubierto por
-- el "when 'admin' then true" de arriba): gestionar roles es cosa de
-- dirección, no algo que un manager deba heredar por defecto.

-- =============================================================================
-- 2 · TABLA DE PLANTILLAS
-- =============================================================================
create table if not exists public.roles_personalizados (
  id               uuid primary key default gen_random_uuid(),
  nombre           text not null unique check (length(trim(nombre)) between 2 and 60),
  descripcion      text not null default '',
  basado_en        public.rol_usuario not null default 'commercial',
  permisos         jsonb not null default '{}'::jsonb,
  -- ids del array MENU del panel (p.ej. 'dashboard','contactos','automation').
  -- Vacío ({}) significa "usa el filtro por defecto de basado_en", no "ninguno".
  modulos_visibles text[] not null default '{}',
  creado_por       uuid references public.perfiles(id) on delete set null,
  creado           timestamptz not null default now(),
  actualizado      timestamptz not null default now()
);

create or replace function public.marca_actualizado()
returns trigger language plpgsql as $$
begin new.actualizado := now(); return new; end $$;
-- (ya existía desde 01-esquema.sql; CREATE OR REPLACE es idempotente aquí,
-- se repite solo para que este archivo no dependa de que 01 la deje intacta)

drop trigger if exists roles_pers_actualizado on public.roles_personalizados;
create trigger roles_pers_actualizado before update on public.roles_personalizados
  for each row execute function public.marca_actualizado();

-- =============================================================================
-- 3 · CAMPOS NUEVOS EN PERFILES
-- =============================================================================
alter table public.perfiles
  add column if not exists modulos_visibles text[],
  add column if not exists rol_personalizado_id uuid references public.roles_personalizados(id) on delete set null;

comment on column public.perfiles.modulos_visibles is
  'Ids del array MENU del panel. NULL = usa el filtro por defecto del rol base. No vacío = solo esas pestañas, sea cual sea el rol.';

-- Nadie decide solo qué pestañas ve ni qué plantilla tiene aplicada: es la
-- misma clase de campo que rol/estado/permisos, así que se protege igual.
create or replace function public.impide_autoescalada()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and auth.uid() = new.id then
    if new.rol is distinct from old.rol
       or new.estado is distinct from old.estado
       or new.permisos is distinct from old.permisos
       or new.debe_cambiar is distinct from old.debe_cambiar
       or new.doble_factor is distinct from old.doble_factor
       or new.modulos_visibles is distinct from old.modulos_visibles
       or new.rol_personalizado_id is distinct from old.rol_personalizado_id then
      raise exception 'No puedes cambiar tu propio rol, estado, permisos, doble factor, la marca de cambio de contraseña ni tus módulos visibles.'
        using errcode = 'insufficient_privilege', hint = 'AUTO_ESCALADA';
    end if;
  end if;
  return new;
end $$;

-- =============================================================================
-- 4 · RLS · solo quien gestiona roles
-- =============================================================================
alter table public.roles_personalizados enable row level security;

drop policy if exists roles_pers_lee   on public.roles_personalizados;
drop policy if exists roles_pers_crea  on public.roles_personalizados;
drop policy if exists roles_pers_edita on public.roles_personalizados;
drop policy if exists roles_pers_borra on public.roles_personalizados;

create policy roles_pers_lee on public.roles_personalizados
  for select using (public.puedo('roles.gestionar'));
create policy roles_pers_crea on public.roles_personalizados
  for insert with check (public.puedo('roles.gestionar') and creado_por = auth.uid());
create policy roles_pers_edita on public.roles_personalizados
  for update using (public.puedo('roles.gestionar')) with check (public.puedo('roles.gestionar'));
create policy roles_pers_borra on public.roles_personalizados
  for delete using (public.puedo('roles.gestionar'));

grant select, insert, update, delete on public.roles_personalizados to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- El backfill de 07-contactos.sql fusionaba solo claves 'contactos.%'. Este
-- permiso es nuevo y distinto, así que se fusiona aparte, sin tocar nada
-- de lo que un admin ya haya personalizado a mano.
update public.perfiles
set permisos = permisos || jsonb_build_object('roles.gestionar', rol = 'admin')
where not (permisos ? 'roles.gestionar');

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from public.permisos_catalogo where clave = 'roles.gestionar') as permiso_nuevo,
  (select count(*) from pg_policies where schemaname='public'
     and tablename='roles_personalizados') as politicas,
  (select count(*) from information_schema.columns where table_schema='public'
     and table_name='perfiles' and column_name in ('modulos_visibles','rol_personalizado_id')) as columnas_nuevas;
-- Esperado: permiso_nuevo = 1, politicas = 4, columnas_nuevas = 2.
