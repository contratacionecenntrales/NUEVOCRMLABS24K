-- =============================================================================
-- LABS COMMAND CENTER 360™ · Endurecimiento de RLS
-- Ejecutar DESPUÉS de 05-firma-contratos.sql
--
-- Cierra agujeros encontrados en una auditoría de seguridad completa del
-- esquema. Ninguno de ellos rompe nada que la aplicación use hoy: se
-- comprobó primero qué llama realmente el panel (index.html/firmar.html) y
-- las funciones SECURITY DEFINER antes de retirar cada permiso.
-- =============================================================================

-- =============================================================================
-- 1 · CONTRATOS: nadie edita su propia firma
-- La política contratos_edita (04-mission-contratos.sql) permite a cada
-- gestor actualizar SU contrato, y el grant de tabla no distinguía columnas:
-- un comercial podía hacer PATCH directo a /contratos y poner estado=
-- 'Firmado', inventarse firma_img/firma_ip/firmado_ts, o resetear
-- token_usado para reabrir un enlace ya gastado — sin pasar nunca por
-- firma_contrato() ni por sus validaciones. El panel jamás hace este UPDATE
-- directo (solo usa sbInsert al crear y el RPC nuevo_enlace_firma para
-- emitir enlaces), así que restringir estas columnas no quita nada real.
--
-- Los permisos por columna no afectan a nuevo_enlace_firma()/firma_contrato():
-- son SECURITY DEFINER y escriben con los privilegios de su propietario, no
-- con los de "authenticated".
-- =============================================================================
revoke update on public.contratos from authenticated;
grant update (
  cliente, cif, domicilio, representante, email, telefono,
  servicio, setup, mensual, meses, iva, inicio, observaciones,
  gestor_id, expediente_id, documento_ruta
) on public.contratos to authenticated;

-- =============================================================================
-- 2 · BITÁCORA, ACCESOS DE RAÍZ Y ACCIONES DE AGENTE: nadie inserta a mano
-- Las tres tablas solo se escriben desde disparadores o integraciones
-- SECURITY DEFINER (anota_cambio_perfil, la Edge Function con la clave de
-- servicio, los webhooks de los agentes). Las políticas "for insert with
-- check (auth.uid() is not null)" no protegían nada de eso — solo abrían la
-- puerta a que cualquier usuario autenticado insertara directamente una fila
-- falsa (un acceso de raíz inventado, una entrada de bitácora atribuida a
-- otra persona, una acción de agente "aprobada" por alguien que no la vio).
-- Al quitar la política, con RLS activada la inserción se deniega por
-- defecto para "authenticated"; el REVOKE es cinturón y tirantes.
-- =============================================================================
drop policy if exists bitacora_inserta   on public.bitacora;
drop policy if exists accesos_raiz_inserta on public.accesos_raiz;
drop policy if exists acciones_crea      on public.agente_acciones;

revoke insert on public.bitacora, public.accesos_raiz, public.agente_acciones from authenticated;

-- =============================================================================
-- 3 · EXPEDIENTE_DOCS: el que sube el documento no puede firmarlo con otro nombre
-- =============================================================================
drop policy if exists expdoc_crea on public.expediente_docs;
create policy expdoc_crea on public.expediente_docs
  for insert with check (public.puedo('exp.docs') and subido_por = auth.uid());

-- =============================================================================
-- 4 · PERFILES: nadie se auto-restaura el doble factor ni el "debe cambiar clave"
-- impide_autoescalada ya bloqueaba que uno se cambiara su propio rol, estado
-- o permisos. Le faltaban dos columnas que también son controles de
-- seguridad, no datos de contacto: debe_cambiar (obliga a rotar una
-- contraseña temporal) y doble_factor. Sin esto, quien recibe una
-- contraseña provisional podía poner debe_cambiar=false sin cambiarla, o
-- cualquiera podía apagarse su propio 2FA.
-- =============================================================================
create or replace function public.impide_autoescalada()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and auth.uid() = new.id then
    if new.rol is distinct from old.rol
       or new.estado is distinct from old.estado
       or new.permisos is distinct from old.permisos
       or new.debe_cambiar is distinct from old.debe_cambiar
       or new.doble_factor is distinct from old.doble_factor then
      raise exception 'No puedes cambiar tu propio rol, estado, permisos, doble factor ni la marca de cambio de contraseña.'
        using errcode = 'insufficient_privilege', hint = 'AUTO_ESCALADA';
    end if;
  end if;
  return new;
end $$;

-- =============================================================================
-- 5 · PROTEGE_RAIZ: no fiarse del silencio cuando aún no existe ninguna raíz
-- El disparador original solo vigilaba las cuentas que YA eran raíz
-- (old.raiz) o la unicidad cuando ya existía una. Si 02-cuenta-raiz.sql
-- nunca llegó a ejecutarse (o su fila se borró a mano), no hay ninguna raíz
-- todavía, la comprobación de unicidad no encuentra nada que impedirle, y
-- CUALQUIER usuario autenticado podría poner raiz=true en su propia fila y
-- convertirse en el Super Administrador. Ahora, mientras no exista ya una
-- cuenta de raíz, solo una llamada sin sesión de usuario (auth.uid() is
-- null: la Edge Function con la clave de servicio, o un script ejecutado
-- desde el editor SQL) puede crear la primera.
-- =============================================================================
create or replace function public.protege_raiz()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_raiz_previa boolean;
begin
  if (tg_op = 'DELETE') then
    if old.raiz then
      raise exception 'El Super Administrador de raíz no se puede eliminar.'
        using errcode = 'check_violation', hint = 'RAIZ_INDESTRUCTIBLE';
    end if;
    return old;
  end if;

  -- OLD no existe todavía en un disparador BEFORE INSERT: se calcula aparte
  -- para no tocar OLD fuera de un bloque que sepa que tg_op = 'UPDATE'.
  if tg_op = 'UPDATE' then
    v_raiz_previa := old.raiz;
  else
    v_raiz_previa := false;
  end if;

  if (tg_op = 'UPDATE' and v_raiz_previa) then
    if new.email is distinct from old.email then
      raise exception 'El correo de la cuenta de raíz no se cambia.'
        using errcode = 'check_violation', hint = 'RAIZ_EMAIL_FIJO';
    end if;
    if new.estado is distinct from 'Activo' then
      raise exception 'La cuenta de raíz está siempre activa.'
        using errcode = 'check_violation', hint = 'RAIZ_SIEMPRE_ACTIVA';
    end if;
    if new.rol is distinct from 'admin' then
      raise exception 'La cuenta de raíz es administradora de forma permanente.'
        using errcode = 'check_violation', hint = 'RAIZ_ROL_FIJO';
    end if;
    if new.raiz is distinct from true then
      raise exception 'La marca de raíz no se puede retirar.'
        using errcode = 'check_violation', hint = 'RAIZ_MARCA_FIJA';
    end if;
    new.permisos     := public.permisos_de_rol('admin');
    new.doble_factor := true;
  end if;

  -- Unicidad: igual en INSERT y en UPDATE.
  if (new.raiz and exists (select 1 from public.perfiles
                           where raiz and id <> new.id)) then
    raise exception 'Ya existe un Super Administrador de raíz.'
      using errcode = 'unique_violation', hint = 'RAIZ_UNICA';
  end if;

  -- Se está ACTIVANDO la marca de raíz ahora mismo (alta nueva, o una fila
  -- que no era raíz y pasa a serlo): solo se acepta si la orden no viene de
  -- una sesión de usuario normal (Edge Function con clave de servicio, o el
  -- editor SQL de Supabase). Antes de esto, si nunca se había ejecutado
  -- 02-cuenta-raiz.sql, cualquier "authenticated" podía autoproclamarse raíz
  -- porque la comprobación de unicidad de arriba no encontraba nada que se lo
  -- impidiera.
  if new.raiz and not v_raiz_previa and auth.uid() is not null then
    raise exception 'La cuenta de raíz solo se crea desde 02-cuenta-raiz.sql o la Edge Function administrativa.'
      using errcode = 'insufficient_privilege', hint = 'RAIZ_SOLO_SISTEMA';
  end if;

  if new.raiz then
    new.rol          := 'admin';
    new.estado       := 'Activo';
    new.permisos     := public.permisos_de_rol('admin');
    new.doble_factor := true;
  end if;

  new.actualizado := now();
  return new;
end $$;

-- =============================================================================
-- 6 · FUNCIONES AYUDANTES: privilegio explícito, no el "PUBLIC" por defecto
-- Postgres concede EXECUTE a PUBLIC (incluido "anon") en cuanto se crea una
-- función, salvo que se revoque. Ninguna de estas funciones hacía nada
-- peligroso si "anon" las llamaba (todas dependen de auth.uid(), que "anon"
-- no tiene), pero el principio de mínimo privilegio dice que si no hace
-- falta, no se concede. Se deja tal cual el acceso ya restringido de
-- nuevo_enlace_firma/contrato_para_firma/firma_contrato (05-firma-contratos.sql).
-- =============================================================================
revoke execute on function public.mi_rol()             from public;
revoke execute on function public.soy_admin()          from public;
revoke execute on function public.puedo(text)          from public;
revoke execute on function public.permisos_de_rol(public.rol_usuario) from public;
revoke execute on function public.cabecera(text)       from public;
revoke execute on function public.ip_peticion()        from public;

grant execute on function public.mi_rol()             to authenticated;
grant execute on function public.soy_admin()          to authenticated;
grant execute on function public.puedo(text)          to authenticated;
grant execute on function public.permisos_de_rol(public.rol_usuario) to authenticated;
grant execute on function public.cabecera(text)       to anon, authenticated;
grant execute on function public.ip_peticion()        to anon, authenticated;

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from information_schema.column_privileges
    where table_schema='public' and table_name='contratos'
      and grantee='authenticated' and privilege_type='UPDATE'
      and column_name in ('estado','token','token_usado','firma_img','firmado_ts')) as columnas_firma_aun_editables,
  (select count(*) from pg_policies
    where schemaname='public' and tablename in ('bitacora','accesos_raiz','agente_acciones')
      and cmd = 'INSERT') as politicas_insert_restantes;
-- Ambas columnas de comprobación deben devolver 0.
