-- =============================================================================
-- LABS COMMAND CENTER 360™ · El Jefe de Equipo gestiona a su equipo
-- Ejecutar DESPUÉS de 16-alta-por-sql.sql. Se puede volver a ejecutar.
--
-- Hasta ahora solo el Administrador podía editar fichas ajenas. Con esto, el
-- Jefe de Equipo puede, SOLO sobre las personas que tiene a su cargo:
--   · editar sus datos (nombre, teléfono, empresa, CIF...);
--   · cambiarles el rol entre Gestión Comercial y Back Office;
--   · cambiarles el superior (a sí mismo o a otra persona de más rango);
--   · bloquearlas (Suspendido / Dado de baja) y reactivarlas;
--   · restablecer su contraseña y borrar su cuenta.
-- No puede: subir a nadie a Jefe ni a Administrador, tocar permisos sueltos,
-- plantillas de rol ni módulos visibles, ni cambiar correos. Eso lo vigila
-- un disparador, no la pantalla.
--
-- Restablecer contraseña y borrar también funcionan aquí para el
-- Administrador, sin depender de la Edge Function.
-- =============================================================================

do $$
begin
  if to_regprocedure('public.rango(public.rol_usuario, boolean)') is null then
    raise exception 'Ejecuta antes 14-superiores.sql.';
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- 1 · ¿PUEDO GESTIONAR A ESTA PERSONA?
-- Admin: a cualquiera menos la raíz. Jefe de Equipo: a quien tiene a su cargo
-- y es de menor rango.
-- -----------------------------------------------------------------------------
create or replace function public.gestiono(p_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1
    from public.perfiles yo, public.perfiles el
    where yo.id = auth.uid() and yo.estado = 'Activo'
      and el.id = p_id and not el.raiz and el.id <> yo.id
      and ( yo.raiz or yo.rol = 'admin'
            or (yo.rol = 'manager' and el.superior_id = yo.id
                and public.rango(el.rol, el.raiz) < public.rango(yo.rol, yo.raiz)) )
  );
$$;
revoke execute on function public.gestiono(uuid) from public, anon;
grant  execute on function public.gestiono(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- 2 · POLÍTICA: el jefe puede actualizar las fichas de su equipo
-- -----------------------------------------------------------------------------
drop policy if exists perfiles_jefe_edita on public.perfiles;
create policy perfiles_jefe_edita on public.perfiles
  for update using (public.gestiono(id)) with check (true);
-- El «with check (true)» es a propósito: lo que se puede cambiar lo limita el
-- disparador de abajo, que ve la fila antes y después.

-- -----------------------------------------------------------------------------
-- 3 · LÍMITES DEL JEFE DE EQUIPO (disparador)
-- -----------------------------------------------------------------------------
create or replace function public.limita_jefe()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_yo public.perfiles%rowtype;
begin
  if auth.uid() is null or auth.uid() = new.id then return new; end if;
  select * into v_yo from public.perfiles where id = auth.uid();
  if not found or v_yo.raiz or v_yo.rol = 'admin' then return new; end if;   -- el admin, sin límites extra

  -- A partir de aquí, un jefe de equipo editando a alguien de su equipo.
  if new.rol not in ('commercial', 'backoffice') then
    raise exception 'Un Jefe de Equipo solo puede asignar los roles Gestión Comercial o Back Office.'
      using errcode = 'insufficient_privilege', hint = 'ROL_NO_PERMITIDO';
  end if;
  if new.email is distinct from old.email then
    raise exception 'El correo solo lo cambia un Administrador.'
      using errcode = 'insufficient_privilege', hint = 'CORREO_SOLO_ADMIN';
  end if;

  -- Lo que no es suyo se queda como estaba; los permisos siguen al rol.
  new.raiz                 := old.raiz;
  new.modulos_visibles     := old.modulos_visibles;
  new.rol_personalizado_id := old.rol_personalizado_id;
  new.api_token            := old.api_token;
  new.permisos := case when new.rol is distinct from old.rol
                       then public.permisos_de_rol(new.rol) else old.permisos end;
  return new;
end $$;

drop trigger if exists perfiles_limita_jefe on public.perfiles;
create trigger perfiles_limita_jefe
  before update on public.perfiles
  for each row execute function public.limita_jefe();

-- -----------------------------------------------------------------------------
-- 4 · RESTABLECER CONTRASEÑA
-- -----------------------------------------------------------------------------
create or replace function public.restablece_clave(p_id uuid, p_password text)
returns boolean language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.gestiono(p_id) then
    raise exception 'Solo puedes restablecer la contraseña de las personas que gestionas.'
      using hint = 'NO_GESTIONAS';
  end if;
  if p_password is null or length(p_password) < 10 or length(p_password) > 200
     or p_password !~ '[A-ZÁÉÍÓÚÑ]' or p_password !~ '[a-záéíóúñ]'
     or p_password !~ '[0-9]' or p_password !~ '[^A-Za-z0-9]' then
    raise exception 'La contraseña necesita al menos 10 caracteres, con mayúscula, minúscula, número y símbolo.'
      using hint = 'CLAVE_DEBIL';
  end if;

  update auth.users
     set encrypted_password = extensions.crypt(p_password, extensions.gen_salt('bf')),
         updated_at = now()
   where id = p_id;
  update public.perfiles set debe_cambiar = true where id = p_id;
  delete from public.sesiones where usuario_id = p_id;

  insert into public.bitacora (actor_id, actor_nombre, actor_rol, destino_id, destino_nombre, accion, detalle)
  select yo.id, trim(yo.nombre || ' ' || yo.apellidos), yo.rol::text,
         el.id, trim(el.nombre || ' ' || el.apellidos), 'Contraseña restablecida',
         'Deberá cambiarla en el próximo acceso. Sesiones cerradas.'
  from public.perfiles yo, public.perfiles el where yo.id = auth.uid() and el.id = p_id;
  return true;
end $$;
revoke execute on function public.restablece_clave(uuid, text) from public, anon;
grant  execute on function public.restablece_clave(uuid, text) to authenticated;

-- -----------------------------------------------------------------------------
-- 5 · BORRAR CUENTA (identidad y ficha)
-- -----------------------------------------------------------------------------
create or replace function public.borra_usuario(p_id uuid)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if not public.gestiono(p_id) then
    raise exception 'Solo puedes borrar las cuentas de las personas que gestionas.'
      using hint = 'NO_GESTIONAS';
  end if;
  -- La bitácora del borrado la escribe el disparador de perfiles.
  delete from public.perfiles where id = p_id;
  delete from auth.users where id = p_id;
  return true;
end $$;
revoke execute on function public.borra_usuario(uuid) from public, anon;
grant  execute on function public.borra_usuario(uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select
  (select count(*) from pg_proc where proname in ('gestiono','limita_jefe','restablece_clave','borra_usuario')) as funciones,
  (select count(*) from pg_policies where tablename = 'perfiles' and policyname = 'perfiles_jefe_edita') as politica;
-- Esperado: funciones = 4, politica = 1
