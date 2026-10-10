-- =============================================================================
-- LABS COMMAND CENTER 360™ · Alta delegada de agentes
-- Ejecutar DESPUÉS de 11-soporte-global.sql. Se puede volver a ejecutar.
--
-- Hasta ahora solo el Administrador podía dar de alta cuentas. Este guion
-- crea el permiso «sys.alta_agentes»: quien lo tenga puede crear cuentas de
-- Gestión Comercial (agentes) y nada más —ni otros roles, ni restablecer
-- contraseñas, ni borrar—. La Edge Function «admin-usuarios» lo comprueba
-- en el servidor y fuerza el rol; el panel solo lo refleja.
--
-- No entra en ningún rol de fábrica salvo admin: se concede a mano, persona
-- a persona, desde Usuarios y Accesos → ficha → Roles y permisos, o con el
-- bloque 3 de abajo.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- 1 · PERMISO NUEVO
-- -----------------------------------------------------------------------------
insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('sys.alta_agentes', 'Sistema', 'Dar de alta agentes',
   'Crear cuentas de Gestión Comercial (solo ese rol)', 172)
on conflict (clave) do update
  set grupo = excluded.grupo, nombre = excluded.nombre,
      descripcion = excluded.descripcion, orden = excluded.orden;

-- Fusiona la clave nueva sin tocar lo que un admin ya haya personalizado.
update public.perfiles
set permisos = permisos || jsonb_build_object('sys.alta_agentes', rol = 'admin')
where not (permisos ? 'sys.alta_agentes');

-- -----------------------------------------------------------------------------
-- 2 · QUIEN DA DE ALTA AGENTES PUEDE VERLOS
-- Sin esto, una persona con rol Gestión Comercial crearía la cuenta y dejaría
-- de verla al recargar, porque RLS solo le enseña su propia ficha. Solo lectura
-- y solo de cuentas de agente: no ve administradores, jefes ni back office.
-- -----------------------------------------------------------------------------
drop policy if exists perfiles_lee_agentes on public.perfiles;
create policy perfiles_lee_agentes on public.perfiles
  for select using (rol = 'commercial' and public.puedo('sys.alta_agentes'));

-- -----------------------------------------------------------------------------
-- 3 · CONCEDER EL PERMISO A MARÍA
-- Sustituye el correo por el suyo y ejecuta. (También se puede hacer desde el
-- panel: Usuarios y Accesos → su ficha → Roles y permisos → «Dar de alta
-- agentes» → Guardar cambios.)
-- -----------------------------------------------------------------------------
-- update public.perfiles
-- set permisos = permisos || '{"sys.alta_agentes": true}'::jsonb
-- where email = 'CORREO-DE-MARIA@labs24k.com';

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select
  (select count(*) from public.permisos_catalogo where clave = 'sys.alta_agentes') as permiso_nuevo,
  (select count(*) from pg_policies where schemaname = 'public'
     and tablename = 'perfiles' and policyname = 'perfiles_lee_agentes')        as politica_nueva,
  (select string_agg(nombre || ' ' || apellidos || ' <' || email || '>', ', ')
     from public.perfiles
    where rol <> 'admin' and (permisos ->> 'sys.alta_agentes')::boolean)        as con_alta_delegada;
-- Esperado: permiso_nuevo = 1, politica_nueva = 1, y en con_alta_delegada
-- aparece María en cuanto se le conceda.
