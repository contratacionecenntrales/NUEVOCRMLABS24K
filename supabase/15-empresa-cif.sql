-- =============================================================================
-- LABS COMMAND CENTER 360™ · Empresa y CIF en la ficha de cada usuario
-- Ejecutar DESPUÉS de 14-superiores.sql. Se puede volver a ejecutar.
--
-- Dos datos de contacto más, editables desde Usuarios y Accesos (ficha →
-- Información) por el Administrador, y visibles en la tabla de usuarios.
-- Son datos de contacto, no de permisos: cada uno puede corregir los suyos
-- desde su propia ficha, igual que el teléfono.
-- =============================================================================

alter table public.perfiles
  add column if not exists empresa text not null default '',
  add column if not exists cif     text not null default '';

do $$
begin
  if not exists (select 1 from pg_constraint where conname = 'perfiles_empresa_largo') then
    alter table public.perfiles add constraint perfiles_empresa_largo check (length(empresa) <= 120);
  end if;
  if not exists (select 1 from pg_constraint where conname = 'perfiles_cif_formato') then
    -- Letras, números y guiones; vacío si no tiene.
    alter table public.perfiles add constraint perfiles_cif_formato check (cif ~ '^[A-Za-z0-9-]{0,20}$');
  end if;
end $$;

comment on column public.perfiles.empresa is 'Empresa a la que pertenece (por ejemplo, la sociedad del agente).';
comment on column public.perfiles.cif     is 'CIF o NIF de esa empresa.';

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select count(*) as columnas_nuevas
from information_schema.columns
where table_schema = 'public' and table_name = 'perfiles' and column_name in ('empresa', 'cif');
-- Esperado: columnas_nuevas = 2
