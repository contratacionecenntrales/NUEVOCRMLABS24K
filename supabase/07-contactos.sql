-- =============================================================================
-- LABS COMMAND CENTER 360™ · Módulo de Contactos (leads y clientes)
-- Ejecutar DESPUÉS de 06-endurecimiento.sql
--
-- Ficha individual por contacto con cuatro áreas:
--   1. Documentación      · contacto_documentos + bucket "documentos"
--   2. Especificaciones   · columna de texto estructurado en la propia tabla
--   3. Actualizaciones    · contacto_eventos (historial, solo se añade)
--   4. Comentarios        · contacto_comentarios (notas rápidas del equipo)
--
-- Mismo criterio de seguridad que el resto del esquema: cada comercial ve y
-- gestiona SUS contactos; dirección y back office los ven todos. Los dos
-- historiales (eventos y comentarios) son de solo-añadir, igual que la
-- bitácora — no hay política de UPDATE ni DELETE, así que nadie reescribe
-- lo que ya se dijo.
-- =============================================================================

-- =============================================================================
-- 1 · PERMISOS NUEVOS
-- =============================================================================
insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('contactos.ver',      'Contactos', 'Ver contactos',            'Consultar leads y clientes de la cartera', 200),
  ('contactos.crea',     'Contactos', 'Crear contactos',          'Dar de alta un nuevo lead o cliente', 210),
  ('contactos.editar',   'Contactos', 'Editar ficha de contacto', 'Datos, estado y especificaciones técnicas', 220),
  ('contactos.notas',    'Contactos', 'Añadir seguimiento',       'Anotar actualizaciones en el historial', 230),
  ('contactos.comentar', 'Contactos', 'Comentar',                 'Notas internas rápidas del equipo', 240),
  ('contactos.docs',     'Contactos', 'Subir documentación',      'Adjuntar contratos, briefings y anexos', 250),
  ('contactos.borrar',   'Contactos', 'Eliminar contactos',       'Borrado de fichas y documentos', 260)
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

-- Los usuarios ya existentes tienen su columna "permisos" congelada en el
-- momento en que se creó su cuenta o cambió de rol: sustituir la función no
-- les añade las claves nuevas por sí solo. Se fusionan (no se sobrescribe
-- nada existente) para no perder excepciones concedidas a mano.
update public.perfiles p
set permisos = p.permisos || (
  select coalesce(jsonb_object_agg(c.clave,
    case p.rol
      when 'admin' then true
      when 'manager' then true
      when 'commercial' then c.clave in ('contactos.ver','contactos.crea','contactos.editar',
             'contactos.notas','contactos.comentar','contactos.docs')
      when 'backoffice' then c.clave in ('contactos.ver','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar')
    end), '{}'::jsonb)
  from public.permisos_catalogo c
  where c.clave like 'contactos.%'
);

-- =============================================================================
-- 2 · TABLAS
-- =============================================================================
do $$ begin
  create type public.tipo_contacto as enum ('lead','cliente');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.estado_contacto as enum
    ('Nuevo','Contactado','Cualificado','Propuesta enviada','Cliente','Perdido');
exception when duplicate_object then null; end $$;

create table if not exists public.contactos (
  id            bigserial primary key,
  tipo          public.tipo_contacto not null default 'lead',
  nombre        text not null check (length(trim(nombre)) between 2 and 120),
  empresa       text not null default '',
  email         text not null default '',
  prefijo       text not null default '+34' check (prefijo ~ '^\+\d{1,3}$'),
  telefono      text not null default '',
  origen        text not null default '',
  estado        public.estado_contacto not null default 'Nuevo',
  -- "Especificaciones técnicas": requerimientos del cliente, integraciones
  -- activas o configuraciones del proyecto. Texto libre a propósito: cada
  -- lead trae necesidades distintas y forzar columnas fijas solo estorbaría.
  especificaciones text not null default '',
  gestor_id     uuid references public.perfiles(id) on delete set null,
  expediente_id bigint references public.expedientes(id) on delete set null,
  creado        timestamptz not null default now(),
  actualizado   timestamptz not null default now()
);
create index if not exists contactos_gestor_idx on public.contactos(gestor_id);
create index if not exists contactos_estado_idx on public.contactos(estado);

drop trigger if exists contactos_actualizado on public.contactos;
create trigger contactos_actualizado before update on public.contactos
  for each row execute function public.marca_actualizado();

-- --- 2.a Actualizaciones y notas de seguimiento (historial, solo se añade) --
create table if not exists public.contacto_eventos (
  id          bigserial primary key,
  contacto_id bigint not null references public.contactos(id) on delete cascade,
  autor_id    uuid references public.perfiles(id) on delete set null,
  tipo        text not null default 'nota' check (tipo in ('estado','evento','nota')),
  texto       text not null check (length(trim(texto)) > 0 and length(texto) <= 2000),
  ts          timestamptz not null default now()
);
create index if not exists contacto_eventos_idx on public.contacto_eventos(contacto_id, ts desc);

-- --- 2.b Comentarios interactivos (notas rápidas del equipo) ---------------
create table if not exists public.contacto_comentarios (
  id          bigserial primary key,
  contacto_id bigint not null references public.contactos(id) on delete cascade,
  autor_id    uuid references public.perfiles(id) on delete set null,
  texto       text not null check (length(trim(texto)) > 0 and length(texto) <= 2000),
  ts          timestamptz not null default now()
);
create index if not exists contacto_comentarios_idx on public.contacto_comentarios(contacto_id, ts desc);

-- --- 2.c Documentación (metadatos; el archivo vive en el bucket "documentos") --
create table if not exists public.contacto_documentos (
  id           bigserial primary key,
  contacto_id  bigint not null references public.contactos(id) on delete cascade,
  nombre       text not null,
  tipo         text not null default '',
  ruta         text not null,      -- p.ej. contactos/42/1699999999-contrato.pdf
  tamano_bytes bigint,
  subido_por   uuid references public.perfiles(id) on delete set null,
  ts           timestamptz not null default now()
);
create index if not exists contacto_documentos_idx on public.contacto_documentos(contacto_id, ts desc);

-- =============================================================================
-- 3 · RLS
-- =============================================================================
alter table public.contactos            enable row level security;
alter table public.contacto_eventos     enable row level security;
alter table public.contacto_comentarios enable row level security;
alter table public.contacto_documentos  enable row level security;

drop policy if exists contactos_lee   on public.contactos;
drop policy if exists contactos_crea  on public.contactos;
drop policy if exists contactos_edita on public.contactos;
drop policy if exists contactos_borra on public.contactos;

create policy contactos_lee on public.contactos
  for select using (
    public.puedo('contactos.ver') and
    (public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid())
  );
create policy contactos_crea on public.contactos
  for insert with check (public.puedo('contactos.crea') and gestor_id = auth.uid());
create policy contactos_edita on public.contactos
  for update using (
    public.puedo('contactos.editar') and
    (public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid())
  ) with check (
    public.puedo('contactos.editar') and
    (public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid())
  );
create policy contactos_borra on public.contactos
  for delete using (public.puedo('contactos.borrar'));

-- --- eventos: se lee lo del contacto propio o de toda la cartera si aplica,
--     se inserta pinchando el autor a quien de verdad ha iniciado sesión ----
drop policy if exists contacto_eventos_lee  on public.contacto_eventos;
drop policy if exists contacto_eventos_crea on public.contacto_eventos;
create policy contacto_eventos_lee on public.contacto_eventos
  for select using (
    public.puedo('contactos.ver') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
create policy contacto_eventos_crea on public.contacto_eventos
  for insert with check (
    autor_id = auth.uid() and public.puedo('contactos.notas') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
-- Sin UPDATE ni DELETE: es un historial, no se reescribe.

drop policy if exists contacto_comentarios_lee  on public.contacto_comentarios;
drop policy if exists contacto_comentarios_crea on public.contacto_comentarios;
create policy contacto_comentarios_lee on public.contacto_comentarios
  for select using (
    public.puedo('contactos.ver') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
create policy contacto_comentarios_crea on public.contacto_comentarios
  for insert with check (
    autor_id = auth.uid() and public.puedo('contactos.comentar') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
-- Sin UPDATE ni DELETE a propósito: si alguien se equivoca en una nota rápida,
-- añade un comentario nuevo aclarándolo, igual que en un chat real.

drop policy if exists contacto_docs_lee   on public.contacto_documentos;
drop policy if exists contacto_docs_crea  on public.contacto_documentos;
drop policy if exists contacto_docs_borra on public.contacto_documentos;
create policy contacto_docs_lee on public.contacto_documentos
  for select using (
    public.puedo('contactos.ver') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
create policy contacto_docs_crea on public.contacto_documentos
  for insert with check (
    subido_por = auth.uid() and public.puedo('contactos.docs') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );
create policy contacto_docs_borra on public.contacto_documentos
  for delete using (
    public.puedo('contactos.borrar') and exists (
      select 1 from public.contactos c where c.id = contacto_id
        and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
    )
  );

grant select, insert, update, delete on public.contactos to authenticated;
grant select, insert on public.contacto_eventos, public.contacto_comentarios to authenticated;
grant select, insert, delete on public.contacto_documentos to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- =============================================================================
-- 4 · ALMACÉN · documentos de contacto en el bucket "documentos"
-- Ruta obligatoria: contactos/<contacto_id>/<archivo>. Sin esa forma, ninguna
-- política de abajo la reconoce y Storage la deniega por defecto.
-- =============================================================================
drop policy if exists contactos_docs_lee_obj   on storage.objects;
drop policy if exists contactos_docs_sube_obj  on storage.objects;
drop policy if exists contactos_docs_borra_obj on storage.objects;

create policy contactos_docs_lee_obj on storage.objects for select using (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.ver')
  and exists (
    select 1 from public.contactos c
    where c.id::text = (storage.foldername(name))[2]
      and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
  )
);
create policy contactos_docs_sube_obj on storage.objects for insert with check (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.docs')
  and exists (
    select 1 from public.contactos c
    where c.id::text = (storage.foldername(name))[2]
      and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
  )
);
create policy contactos_docs_borra_obj on storage.objects for delete using (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.borrar')
  and exists (
    select 1 from public.contactos c
    where c.id::text = (storage.foldername(name))[2]
      and (public.mi_rol() in ('admin','manager','backoffice') or c.gestor_id = auth.uid())
  )
);

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from public.permisos_catalogo where clave like 'contactos.%') as permisos_nuevos,
  (select count(*) from pg_policies where schemaname='public'
     and tablename in ('contactos','contacto_eventos','contacto_comentarios','contacto_documentos')) as politicas_tabla,
  (select count(*) from pg_policies where schemaname='storage' and tablename='objects'
     and policyname like 'contactos_docs_%') as politicas_storage;
-- Esperado: permisos_nuevos = 7, politicas_tabla = 11, politicas_storage = 3.
