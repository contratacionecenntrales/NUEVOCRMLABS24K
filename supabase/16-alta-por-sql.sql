-- =============================================================================
-- LABS COMMAND CENTER 360™ · Alta de usuarios desde la base de datos
-- Ejecutar DESPUÉS de 14-superiores.sql. Se puede volver a ejecutar.
--
-- Hasta ahora el alta de usuarios pasaba solo por la Edge Function
-- «admin-usuarios». Esta función hace lo mismo dentro de la base de datos,
-- igual que 02-cuenta-raiz.sql creó la cuenta de Juan: crea la identidad
-- (auth.users + auth.identities) y la ficha (perfiles) en un solo paso, y si
-- algo falla no se queda nada a medias.
--
-- El panel la usa primero; si no existe, recurre a la Edge Function.
--
-- Quién puede dar de alta qué (se comprueba aquí, en el servidor):
--   · Super Administrador y Administrador: cualquier rol.
--   · Jefe de Equipo: Gestión Comercial y Back Office; quedan a su cargo.
--   · Quien tenga el permiso «sys.alta_agentes»: solo Gestión Comercial.
-- =============================================================================

do $$
begin
  if not exists (select 1 from information_schema.columns
                 where table_schema = 'public' and table_name = 'perfiles'
                   and column_name = 'superior_id') then
    raise exception 'Ejecuta antes 14-superiores.sql.';
  end if;
end $$;

create or replace function public.alta_usuario(
  p_nombre    text,
  p_apellidos text,
  p_email     text,
  p_rol       public.rol_usuario,
  p_password  text,
  p_prefijo   text    default '+34',
  p_telefono  text    default '',
  p_extension text    default '',
  p_google    boolean default false,
  p_superior  uuid    default null
)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_yo       public.perfiles%rowtype;
  v_sup      public.perfiles%rowtype;
  v_permitidos public.rol_usuario[];
  v_email    text := lower(trim(coalesce(p_email, '')));
  v_nombre   text := trim(coalesce(p_nombre, ''));
  v_ape      text := trim(coalesce(p_apellidos, ''));
  v_id       uuid := gen_random_uuid();
  v_rel      text;
  v_superior uuid;
  v_ficha    public.perfiles%rowtype;
begin
  -- 1 · quién lo pide
  select * into v_yo from public.perfiles where id = auth.uid() and estado = 'Activo';
  if not found then
    raise exception 'Sesión no válida o cuenta inactiva.' using hint = 'SIN_SESION';
  end if;

  v_permitidos := case
    when v_yo.raiz or v_yo.rol = 'admin' then array['admin','manager','commercial','backoffice']::public.rol_usuario[]
    when v_yo.rol = 'manager'            then array['commercial','backoffice']::public.rol_usuario[]
    when coalesce((v_yo.permisos ->> 'sys.alta_agentes')::boolean, false)
                                         then array['commercial']::public.rol_usuario[]
    else array[]::public.rol_usuario[] end;

  if cardinality(v_permitidos) = 0 then
    raise exception 'No tienes permiso para dar de alta usuarios (tu cuenta figura como: %).', v_yo.rol
      using hint = 'ROL_INSUFICIENTE';
  end if;
  if not (p_rol = any(v_permitidos)) then
    raise exception 'Con tu rol solo puedes dar de alta: %.', array_to_string(v_permitidos, ', ')
      using hint = 'ROL_NO_PERMITIDO';
  end if;

  -- 2 · datos
  if length(v_nombre) < 2 then
    raise exception 'Nombre no válido.' using hint = 'NOMBRE_INVALIDO';
  end if;
  if v_email !~ '^[^@\s]+@[^@\s]+\.[a-z]{2,}$' then
    raise exception 'Correo no válido.' using hint = 'EMAIL_INVALIDO';
  end if;
  if exists (select 1 from auth.users where lower(email) = v_email)
     or exists (select 1 from public.perfiles where lower(email) = v_email) then
    raise exception 'Ya existe una cuenta con ese correo.' using hint = 'EMAIL_DUPLICADO';
  end if;
  if coalesce(p_prefijo, '') <> '' and p_prefijo !~ '^\+\d{1,3}$' then
    raise exception 'El prefijo debe ser internacional, como +34.' using hint = 'PREFIJO_INVALIDO';
  end if;

  -- 3 · contraseña: la misma política que el panel
  if p_password is null or length(p_password) < 10 or length(p_password) > 200
     or p_password !~ '[A-ZÁÉÍÓÚÑ]' or p_password !~ '[a-záéíóúñ]'
     or p_password !~ '[0-9]' or p_password !~ '[^A-Za-z0-9]' then
    raise exception 'La contraseña necesita al menos 10 caracteres, con mayúscula, minúscula, número y símbolo.'
      using hint = 'CLAVE_DEBIL';
  end if;

  -- 4 · superior: el que elija un admin, o quien da el alta; si no tiene más
  --     rango que la nueva cuenta, cuelga del Super Administrador.
  v_superior := case when (v_yo.raiz or v_yo.rol = 'admin') and p_superior is not null
                     then p_superior else v_yo.id end;
  select * into v_sup from public.perfiles where id = v_superior and estado = 'Activo';
  if not found or public.rango(v_sup.rol, v_sup.raiz) <= public.rango(p_rol, false) then
    select id into v_superior from public.perfiles where raiz limit 1;
  end if;

  -- 5 · número de relación único
  loop
    v_rel := '0-' || (100 + floor(random() * 900))::int || '-' || (100 + floor(random() * 900))::int;
    exit when not exists (select 1 from public.perfiles where rel = v_rel);
  end loop;

  -- 6 · identidad (igual que 02-cuenta-raiz.sql)
  insert into auth.users (
    instance_id, id, aud, role, email, encrypted_password,
    email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
    created_at, updated_at,
    confirmation_token, recovery_token, email_change, email_change_token_new
  ) values (
    '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated',
    v_email, extensions.crypt(p_password, extensions.gen_salt('bf')),
    now(),
    '{"provider":"email","providers":["email"]}'::jsonb,
    jsonb_build_object('nombre', v_nombre, 'apellidos', v_ape),
    now(), now(), '', '', '', ''
  );
  insert into auth.identities (
    id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
  ) values (
    gen_random_uuid(), v_id, v_id::text,
    jsonb_build_object('sub', v_id::text, 'email', v_email, 'email_verified', true),
    'email', null, now(), now()
  );

  -- 7 · ficha
  insert into public.perfiles (
    id, nombre, apellidos, email, prefijo, telefono, extension,
    rol, estado, rel, google, debe_cambiar, permisos, api_token, superior_id
  ) values (
    v_id, v_nombre, v_ape, v_email, coalesce(nullif(p_prefijo, ''), '+34'),
    trim(coalesce(p_telefono, '')), trim(coalesce(p_extension, '')),
    p_rol, 'Activo', v_rel, coalesce(p_google, false), true,
    public.permisos_de_rol(p_rol),
    'lk_' || replace(gen_random_uuid()::text, '-', ''),
    v_superior
  ) returning * into v_ficha;

  -- La bitácora la escribe sola el disparador de perfiles (01-esquema.sql),
  -- con quien ha iniciado sesión como autor.

  return to_jsonb(v_ficha);
end $$;

revoke execute on function public.alta_usuario(text, text, text, public.rol_usuario, text, text, text, text, boolean, uuid) from public, anon;
grant  execute on function public.alta_usuario(text, text, text, public.rol_usuario, text, text, text, text, boolean, uuid) to authenticated;

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select count(*) as funcion_alta from pg_proc where proname = 'alta_usuario';
-- Esperado: funcion_alta = 1
