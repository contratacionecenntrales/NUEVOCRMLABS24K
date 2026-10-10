-- =============================================================================
-- LABS COMMAND CENTER 360™ · Soporte Global de Incidencias (/admin-support-desk)
-- Ejecutar DESPUÉS de 10-soporte.sql
--
-- No crea ninguna tabla ni política nueva sobre tickets: la mesa de trabajo
-- centralizada de soporte.gestionar (admin y manager) YA ve todas las
-- incidencias de todos los roles a través de la política tickets_lee que
-- ya existe. Lo único que añade este archivo es una vista de solo lectura
-- que calcula, a partir de datos reales (prioridad + fecha de apertura),
-- si una incidencia ha superado su plazo de SLA — nada se inventa ni se
-- guarda aparte, es un cálculo sobre las mismas filas de siempre.
--
-- OJO DE SEGURIDAD: la vista se crea con security_invoker = true. Sin esto,
-- una vista en Postgres/Supabase se ejecuta con los permisos de quien la
-- creó (normalmente el rol que corre las migraciones, que salta RLS), y
-- CUALQUIER usuario autenticado vería TODAS las incidencias de TODOS a
-- través de la vista aunque la tabla de debajo se lo impida. Con
-- security_invoker = true la vista respeta la RLS de quien pregunta, igual
-- que si consultara la tabla directamente.
--
-- Regla de la casa: solo se crea. No se toca ninguna tabla, política ni
-- función de 10-soporte.sql.
-- =============================================================================

create or replace view public.tickets_panel
with (security_invoker = true) as
select
  t.*,
  case t.prioridad
    when 'critica' then 4
    when 'alta'    then 24
    when 'media'   then 72
    else 168
  end as sla_horas,
  round(extract(epoch from (now() - t.creado)) / 3600.0, 1) as horas_abierta,
  (
    t.estado not in ('resuelto','cerrado')
    and extract(epoch from (now() - t.creado)) / 3600.0 > (
      case t.prioridad
        when 'critica' then 4
        when 'alta'    then 24
        when 'media'   then 72
        else 168
      end
    )
  ) as sla_vencida
from public.tickets t;

grant select on public.tickets_panel to authenticated;

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from pg_views where schemaname='public' and viewname='tickets_panel') as vista_creada,
  (select coalesce(
     (select option_value from pg_options_to_table(
        (select reloptions from pg_class where oid = 'public.tickets_panel'::regclass)
      ) where option_name = 'security_invoker'),
     'false') = 'true') as security_invoker_activo;
-- Esperado: vista_creada = 1, security_invoker_activo = true. Si esto
-- diera false, la vista se saltaría la RLS de tickets y sería un agujero
-- de seguridad real: cualquier autenticado vería incidencias ajenas.
