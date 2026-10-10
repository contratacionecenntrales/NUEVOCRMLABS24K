-- =============================================================================
-- LABS COMMAND CENTER 360™ · Centro de Descarga de Dosieres
-- Ejecutar DESPUÉS de 08-roles-personalizados.sql
--
-- Repositorio documental corporativo, estructurado por categoría, para los
-- dosieres de servicios de la empresa (PDF/PPTX). Reutiliza el mismo bucket
-- privado "documentos" que ya usan expedientes y contactos, bajo su propio
-- prefijo de ruta (recursos/<id>/archivo) y sus propias políticas — no toca
-- ni las tablas ni las políticas que ya existían sobre ese bucket.
--
-- Regla de la casa para todo módulo nuevo: solo se crea (tablas, políticas,
-- permisos, funciones nuevas). Nada de este archivo modifica una tabla,
-- política o función que no haya creado él mismo, salvo el propio catálogo
-- de permisos (permisos_catalogo), que está diseñado para crecer así desde
-- el principio — igual que hicieron 07 y 08 antes que este.
-- =============================================================================

-- =============================================================================
-- 1 · PERMISOS NUEVOS
-- =============================================================================
insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('recursos.ver',    'Recursos', 'Ver el centro de recursos', 'Consultar y descargar dosieres corporativos', 300),
  ('recursos.subir',  'Recursos', 'Subir dosieres',            'Añadir documentos al repositorio', 310),
  ('recursos.borrar', 'Recursos', 'Eliminar dosieres',         'Retirar documentos del repositorio', 320)
on conflict (clave) do update
  set grupo = excluded.grupo, nombre = excluded.nombre,
      descripcion = excluded.descripcion, orden = excluded.orden;

-- Recursos es un repositorio de empresa: lo ven los cuatro roles de fábrica.
-- Solo admin y manager suben o retiran documentos.
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
             'recursos.ver','recursos.subir','recursos.borrar')
      when 'commercial' then c.clave in ('presu.ver','presu.crear','funnel.ver','exp.ver','exp.docs',
             'com.llamadas','com.wsp',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs',
             'recursos.ver')
      when 'backoffice' then c.clave in ('exp.ver','exp.estado','exp.hitos','exp.docs','exp.borrar',
             'presu.ver','com.llamadas',
             'contactos.ver','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver')
    end), '{}'::jsonb)
  from public.permisos_catalogo c;
$$;

update public.perfiles
set permisos = permisos || jsonb_build_object(
  'recursos.ver',    true,
  'recursos.subir',  rol in ('admin','manager'),
  'recursos.borrar', rol in ('admin','manager')
)
where not (permisos ? 'recursos.ver');

-- =============================================================================
-- 2 · TABLAS
-- =============================================================================
create table if not exists public.recursos (
  id            bigserial primary key,
  categoria     text not null default 'General' check (length(trim(categoria)) between 2 and 60),
  nombre        text not null check (length(trim(nombre)) between 2 and 160),
  descripcion   text not null default '',
  tipo          text not null default 'pdf' check (tipo in ('pdf','pptx')),
  ruta          text not null,      -- p.ej. recursos/17/1699999999-dosier-command-center.pdf
  tamano_bytes  bigint,
  subido_por    uuid references public.perfiles(id) on delete set null,
  creado        timestamptz not null default now(),
  actualizado   timestamptz not null default now()
);
create index if not exists recursos_categoria_idx on public.recursos(categoria);

drop trigger if exists recursos_actualizado on public.recursos;
create trigger recursos_actualizado before update on public.recursos
  for each row execute function public.marca_actualizado();

-- Analítica de descargas: solo se añade, nunca se corrige — un registro de
-- auditoría que se pudiera editar no serviría para nada.
create table if not exists public.recursos_descargas (
  id          bigserial primary key,
  recurso_id  bigint not null references public.recursos(id) on delete cascade,
  usuario_id  uuid references public.perfiles(id) on delete set null,
  ts          timestamptz not null default now()
);
create index if not exists recursos_descargas_idx on public.recursos_descargas(recurso_id, ts desc);

-- =============================================================================
-- 3 · RLS
-- =============================================================================
alter table public.recursos            enable row level security;
alter table public.recursos_descargas  enable row level security;

drop policy if exists recursos_lee   on public.recursos;
drop policy if exists recursos_sube  on public.recursos;
drop policy if exists recursos_borra on public.recursos;

create policy recursos_lee on public.recursos
  for select using (public.puedo('recursos.ver'));
create policy recursos_sube on public.recursos
  for insert with check (public.puedo('recursos.subir') and subido_por = auth.uid());
create policy recursos_borra on public.recursos
  for delete using (public.puedo('recursos.borrar'));
-- Sin política de UPDATE: un dosier no se "edita" in situ — se sube uno
-- nuevo y se retira el anterior, así el registro de qué se descargó cuándo
-- sigue apuntando al archivo exacto que la gente tuvo delante.

drop policy if exists recursos_desc_lee  on public.recursos_descargas;
drop policy if exists recursos_desc_crea on public.recursos_descargas;
create policy recursos_desc_lee on public.recursos_descargas
  for select using (public.mi_rol() in ('admin','manager') or usuario_id = auth.uid());
create policy recursos_desc_crea on public.recursos_descargas
  for insert with check (public.puedo('recursos.ver') and usuario_id = auth.uid());
-- Sin UPDATE ni DELETE: el registro de descargas no se toca desde el panel.

grant select, insert, delete on public.recursos to authenticated;
grant select, insert on public.recursos_descargas to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- =============================================================================
-- 4 · ALMACÉN · dosieres en el bucket "documentos" ya existente
-- Ruta obligatoria: recursos/<recurso_id>/<archivo>. Mismo patrón que ya usa
-- el módulo de Contactos para su propio prefijo dentro del mismo bucket.
-- =============================================================================
drop policy if exists recursos_lee_obj   on storage.objects;
drop policy if exists recursos_sube_obj  on storage.objects;
drop policy if exists recursos_borra_obj on storage.objects;

create policy recursos_lee_obj on storage.objects for select using (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'recursos'
  and public.puedo('recursos.ver')
);
create policy recursos_sube_obj on storage.objects for insert with check (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'recursos'
  and public.puedo('recursos.subir')
);
create policy recursos_borra_obj on storage.objects for delete using (
  bucket_id = 'documentos'
  and (storage.foldername(name))[1] = 'recursos'
  and public.puedo('recursos.borrar')
);

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from public.permisos_catalogo where clave like 'recursos.%') as permisos_nuevos,
  (select count(*) from pg_policies where schemaname='public'
     and tablename in ('recursos','recursos_descargas')) as politicas_tabla,
  (select count(*) from pg_policies where schemaname='storage' and tablename='objects'
     and policyname like 'recursos_%') as politicas_storage;
-- Esperado: permisos_nuevos = 3, politicas_tabla = 5, politicas_storage = 3.
