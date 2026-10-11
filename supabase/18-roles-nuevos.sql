-- =============================================================================
-- LABS COMMAND CENTER 360™ · Roles nuevos: Coordinador y Soporte
-- Ejecutar DESPUÉS de 17-jefe-gestiona-equipo.sql, y SOLO, en su propia
-- ejecución: Postgres no deja usar un valor nuevo de un tipo en la misma
-- tanda en la que se crea. Después, 19-jerarquia-roles.sql.
-- Se puede volver a ejecutar.
--
-- Escala completa (de mayor a menor rango):
--   Superadmin (la cuenta raíz) > Administrador > Coordinador > Jefe de Equipo
--   > Agente / Comercial · Back Office / Tramitación · Soporte
-- =============================================================================

alter type public.rol_usuario add value if not exists 'coordinator';
alter type public.rol_usuario add value if not exists 'support';

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select string_agg(e.enumlabel, ', ' order by e.enumsortorder) as roles
from pg_enum e join pg_type t on t.oid = e.enumtypid
where t.typname = 'rol_usuario';
-- Esperado: admin, manager, commercial, backoffice, coordinator, support
