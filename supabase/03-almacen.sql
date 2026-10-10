-- =============================================================================
-- LABS COMMAND CENTER 360™ · Almacén de archivos (Supabase Storage)
-- Ejecutar DESPUÉS de 01-esquema.sql
--
-- Crea el bucket «documentos», donde viven los contratos, las auditorías en
-- PDF y el material de la Academia. Es PRIVADO: no existe una URL pública que
-- alguien pueda compartir por accidente. Cada descarga pasa por el token de
-- sesión y por las políticas de abajo.
--
-- Estructura de carpetas que espera el panel:
--   expedientes/<id_expediente>/<archivo>   documentación del cliente
--   academia/<curso>/<archivo>              recursos de formación
-- =============================================================================

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values (
  'documentos', 'documentos', false,
  26214400,                                  -- 25 MB por archivo
  array['application/pdf','image/png','image/jpeg','image/webp',
        'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'text/csv','text/plain']
)
on conflict (id) do update
  set public = false,
      file_size_limit = excluded.file_size_limit,
      allowed_mime_types = excluded.allowed_mime_types;

-- --- políticas -------------------------------------------------------------
drop policy if exists docs_lee    on storage.objects;
drop policy if exists docs_sube   on storage.objects;
drop policy if exists docs_borra  on storage.objects;

-- Lee quien pueda ver expedientes. Es el mismo permiso que abre la ficha del
-- cliente: no tendría sentido ver el expediente y no poder abrir su contrato.
create policy docs_lee on storage.objects
  for select using (
    bucket_id = 'documentos' and public.puedo('exp.ver')
  );

-- Sube quien tenga el permiso de documentación.
create policy docs_sube on storage.objects
  for insert with check (
    bucket_id = 'documentos' and public.puedo('exp.docs')
  );

-- Borra solo quien pueda eliminar registros.
create policy docs_borra on storage.objects
  for delete using (
    bucket_id = 'documentos' and public.puedo('exp.borrar')
  );

-- --- comprobación ----------------------------------------------------------
select
  b.id                                   as bucket,
  b.public                               as es_publico,
  (b.file_size_limit / 1048576) || ' MB' as tamano_maximo,
  (select count(*) from pg_policies
   where schemaname = 'storage' and tablename = 'objects'
     and policyname in ('docs_lee','docs_sube','docs_borra')) as politicas
from storage.buckets b
where b.id = 'documentos';
