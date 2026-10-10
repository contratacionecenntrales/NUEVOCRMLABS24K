-- =============================================================================
-- LABS COMMAND CENTER 360™ · Super Administrador de raíz
-- Ejecutar DESPUÉS de 01-esquema.sql
--
-- Crea la identidad de Juan Álvarez en Supabase Auth y su ficha en perfiles,
-- con el distintivo de raíz y todos los permisos.
--
-- SOBRE EL CORREO
--   Se pidió «JÁlvarez@labs24k.com». Una tilde ANTES de la arroba obliga al
--   servidor de correo a hablar SMTPUTF8, que muchos proveedores —Hostalia
--   entre ellos— no admiten: ese buzón no recibiría. Por eso la identidad se
--   guarda sin tilde y el panel acepta las dos grafías como alias.
--
-- ⚠ SOBRE LA CONTRASEÑA — LEER ANTES DE EJECUTAR
--   Se ha puesto la que se pidió: la contraseña ES el propio correo,
--   «jalvarez@labs24k.com». Supabase guarda solo su hash, pero eso no arregla
--   el problema de fondo:
--
--     · El correo es público. Está en la web, en las propuestas y en la firma
--       de cada email que sale de la empresa. No es un secreto.
--     · «usuario = contraseña» es el PRIMER par que prueba cualquier ataque
--       automatizado. No hay que adivinar nada: se deduce.
--     · Esta cuenta es el Super Administrador: da acceso a los expedientes de
--       clientes, sus teléfonos, contratos y facturación. Datos personales de
--       terceros, con lo que eso implica en materia de protección de datos.
--     · No cumple la política que esta misma aplicación exige a los demás
--       usuarios (10 caracteres con mayúscula, minúscula, número y símbolo).
--
--   La cuenta nace con debe_cambiar = true y el panel lo recordará en cada
--   acceso. Cámbiala en cuanto entres. Para poner otra desde el principio,
--   edita la línea `v_clave` de abajo antes de ejecutar el archivo.
--
-- SI PREFIERES NO CREAR EL USUARIO POR SQL
--   Panel de Supabase → Authentication → Users → Add user
--     correo    jalvarez@labs24k.com
--     password  (elige tú una contraseña que cumpla la política corporativa)
--     marca «Auto Confirm User»
--   y después ejecuta SOLO el bloque 2 de este archivo.
-- =============================================================================

-- -----------------------------------------------------------------------------
-- BLOQUE 0 · asegura pgcrypto (crypt/gen_salt) antes de usarlo
-- En un proyecto de Supabase normal ya está instalado en el esquema
-- "extensions"; esto solo evita que el guion falle si por lo que sea no lo
-- estuviera. Sin efecto si ya existe.
-- -----------------------------------------------------------------------------
create extension if not exists pgcrypto with schema extensions;

-- -----------------------------------------------------------------------------
-- BLOQUE 1 · identidad en Supabase Auth
-- -----------------------------------------------------------------------------
do $$
declare
  v_id    uuid;
  v_email text := 'jalvarez@labs24k.com';
  v_clave text := 'CAMBIA-ESTA-CLAVE-ANTES-DE-EJECUTAR';   -- ⚠ obligatorio: ver el aviso de arriba
begin
  select id into v_id from auth.users where email = v_email;

  if v_id is null then
    v_id := gen_random_uuid();

    insert into auth.users (
      instance_id, id, aud, role, email, encrypted_password,
      email_confirmed_at, raw_app_meta_data, raw_user_meta_data,
      created_at, updated_at,
      confirmation_token, recovery_token, email_change, email_change_token_new
    ) values (
      '00000000-0000-0000-0000-000000000000', v_id, 'authenticated', 'authenticated',
      v_email, extensions.crypt(v_clave, extensions.gen_salt('bf')),
      now(),
      '{"provider":"email","providers":["email","google"]}'::jsonb,
      '{"nombre":"Juan","apellidos":"Álvarez","raiz":true}'::jsonb,
      now(), now(), '', '', '', ''
    );

    -- auth.identities es obligatoria en las versiones recientes de GoTrue.
    insert into auth.identities (
      id, user_id, provider_id, identity_data, provider, last_sign_in_at, created_at, updated_at
    ) values (
      gen_random_uuid(), v_id, v_id::text,
      format('{"sub":"%s","email":"%s","email_verified":true}', v_id, v_email)::jsonb,
      'email', now(), now(), now()
    ) on conflict do nothing;

    raise notice 'Identidad de raíz creada: % (%)', v_email, v_id;
  else
    raise notice 'La identidad de raíz ya existía: % (%)', v_email, v_id;
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- BLOQUE 2 · ficha en perfiles
-- Se puede ejecutar por separado si el usuario se creó desde el panel.
-- -----------------------------------------------------------------------------
insert into public.perfiles (
  id, raiz, nombre, apellidos, email, prefijo, telefono, extension,
  rol, estado, rel, google, doble_factor, debe_cambiar,
  permisos, preferencias, api_token, alta
)
select
  u.id, true, 'Juan', 'Álvarez', u.email, '+34', '600 112 233', '101',
  'admin', 'Activo', '0-413-936', true, true, true,
  public.permisos_de_rol('admin'),
  jsonb_build_object(
    'llamadas',       jsonb_build_object('extension','101','desvio','','grabar',true,'buzon',true,
                        'saludo','Has llamado a Labs24k. Deja tu mensaje y te devolvemos la llamada.'),
    'disponibilidad', jsonb_build_object('dias', jsonb_build_object('L',true,'M',true,'X',true,'J',true,
                        'V',true,'S',false,'D',false), 'desde','09:00','hasta','18:00','zona','Europe/Madrid'),
    'calendario',     jsonb_build_object('duracion',30,'margen',10,'antelacion',4,'enlace',''),
    'notificaciones', jsonb_build_object('correo',true,'push',true,'whatsapp',false,
                        'resumen',true,'altas',true,'incidencias',true)
  ),
  'lk_' || encode(extensions.gen_random_bytes(21), 'base64'),
  '2026-01-12'
from auth.users u
where u.email = 'jalvarez@labs24k.com'
on conflict (id) do update
  set raiz = true, rol = 'admin', estado = 'Activo',
      permisos = public.permisos_de_rol('admin'), doble_factor = true;

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN · confirma las DOS tablas, no solo perfiles
-- -----------------------------------------------------------------------------
select
  u.email,
  (u.encrypted_password is not null)             as tiene_hash_en_auth_users,
  (u.email_confirmed_at is not null)             as correo_confirmado,
  exists (select 1 from auth.identities i where i.user_id = u.id) as tiene_identity,
  p.id is not null                               as tiene_ficha_en_perfiles,
  p.rol,
  p.estado,
  p.raiz                                         as es_raiz,
  p.debe_cambiar                                 as debe_cambiar_clave,
  (select count(*) from jsonb_each(p.permisos)
   where value::text = 'true')                   as permisos_concedidos,
  (select count(*) from public.permisos_catalogo) as permisos_totales
from auth.users u
left join public.perfiles p on p.id = u.id
where u.email = 'jalvarez@labs24k.com';
-- Fila esperada: tiene_hash_en_auth_users = true, tiene_identity = true,
-- tiene_ficha_en_perfiles = true, rol = admin, es_raiz = true,
-- permisos_concedidos = permisos_totales. Si esta consulta no devuelve
-- ninguna fila, el BLOQUE 1 no llegó a crear el usuario: revisa los avisos
-- (raise notice) que imprimió al ejecutarlo.
