-- =============================================================================
-- LABS COMMAND CENTER 360™ · Jerarquía completa de roles y privacidad vertical
-- Ejecutar DESPUÉS de 18-roles-nuevos.sql (en otra ejecución). Se puede
-- volver a ejecutar.
--
-- ESCALA (rango)
--   5 Superadmin (la cuenta raíz)
--   4 Administrador
--   3 Coordinador        · coordina a sus Jefes de Equipo y a los Agentes de estos
--   2 Jefe de Equipo     · lidera a sus Agentes
--   1 Agente / Comercial · Back Office / Tramitación · Soporte
--     (los dos últimos son transversales: no dependen de un jefe comercial)
--
-- REGLA GLOBAL
--   · Visibilidad descendente: cada uno ve lo suyo y lo de quien depende de
--     él, a cualquier profundidad (el Coordinador ve a los agentes de sus
--     jefes). Superadmin y Administrador lo ven todo.
--   · Privacidad vertical: nadie ve fichas, métricas ni actividad de sus
--     superiores ni de otras líneas.
--   · Tramitación ve las carteras para tramitar (contactos y contratos);
--     Soporte ve los clientes y las incidencias.
--
-- QUIÉN DA DE ALTA A QUIÉN
--   Administrador: cualquier rol · Coordinador: Jefes de Equipo y Agentes ·
--   Jefe de Equipo: Agentes · con «sys.alta_agentes»: Agentes.
-- =============================================================================

do $$
begin
  if not exists (select 1 from pg_enum e join pg_type t on t.oid = e.enumtypid
                 where t.typname = 'rol_usuario' and e.enumlabel = 'coordinator') then
    raise exception 'Ejecuta antes 18-roles-nuevos.sql (en una ejecución aparte).';
  end if;
  if to_regprocedure('public.alta_usuario(text,text,text,public.rol_usuario,text,text,text,text,boolean,uuid)') is null then
    raise exception 'Ejecuta antes 16-alta-por-sql.sql y 17-jefe-gestiona-equipo.sql.';
  end if;
end $$;

-- =============================================================================
-- 1 · RANGO Y CADENA DE MANDO
-- =============================================================================
create or replace function public.rango(p_rol public.rol_usuario, p_raiz boolean)
returns int language sql immutable as $$
  select case when p_raiz then 5
              when p_rol = 'admin' then 4
              when p_rol = 'coordinator' then 3
              when p_rol = 'manager' then 2
              else 1 end;
$$;

-- ¿Depende p_persona de p_jefe, directa o indirectamente? Sube por la cadena
-- de superiores (hasta 10 niveles, de sobra para esta escala).
create or replace function public.es_subordinado(p_persona uuid, p_jefe uuid)
returns boolean language sql stable security definer set search_path = public as $$
  with recursive cadena(id, sup, n) as (
    select id, superior_id, 0 from public.perfiles where id = p_persona
    union all
    select p.id, p.superior_id, c.n + 1
    from public.perfiles p join cadena c on p.id = c.sup
    where c.n < 10
  )
  select p_persona is not null and p_jefe is not null
     and exists (select 1 from cadena where sup = p_jefe);
$$;
revoke execute on function public.es_subordinado(uuid, uuid) from public, anon;
grant  execute on function public.es_subordinado(uuid, uuid) to authenticated;

-- Roles que puede asignar (dar de alta o poner) una persona.
create or replace function public.roles_asignables(p_quien uuid)
returns public.rol_usuario[] language sql stable security definer set search_path = public as $$
  select case
    when p.raiz or p.rol = 'admin' then
      array['admin','coordinator','manager','commercial','backoffice','support']::public.rol_usuario[]
    when p.rol = 'coordinator' then array['manager','commercial']::public.rol_usuario[]
    when p.rol = 'manager'     then array['commercial']::public.rol_usuario[]
    when coalesce((p.permisos ->> 'sys.alta_agentes')::boolean, false)
                               then array['commercial']::public.rol_usuario[]
    else array[]::public.rol_usuario[] end
  from public.perfiles p where p.id = p_quien and p.estado = 'Activo';
$$;
revoke execute on function public.roles_asignables(uuid) from public, anon;
grant  execute on function public.roles_asignables(uuid) to authenticated;

-- ¿Puedo gestionar a esta persona? Admin: a todos menos la raíz. Coordinador
-- y Jefe de Equipo: a quien depende de ellos y tiene menos rango.
create or replace function public.gestiono(p_id uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select exists (
    select 1
    from public.perfiles yo, public.perfiles el
    where yo.id = auth.uid() and yo.estado = 'Activo'
      and el.id = p_id and not el.raiz and el.id <> yo.id
      and ( yo.raiz or yo.rol = 'admin'
            or (yo.rol in ('coordinator','manager')
                and public.es_subordinado(el.id, yo.id)
                and public.rango(el.rol, el.raiz) < public.rango(yo.rol, yo.raiz)) )
  );
$$;

-- Fichas de agente: admin, o el coordinador / jefe de la línea del agente.
create or replace function public.dirijo_agente(p_agente uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(public.mi_rol() = 'admin', false)
      or (public.mi_rol() in ('coordinator','manager') and public.es_subordinado(p_agente, auth.uid()));
$$;

-- Carteras (contactos, contratos): lo propio, lo de la propia línea, todo si
-- se es admin, y transversal para Tramitación.
create or replace function public.ve_cartera(p_gestor uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select auth.uid() is not null and (
       public.soy_admin()
    or p_gestor = auth.uid()
    or public.mi_rol() = 'backoffice'
    or (public.mi_rol() in ('coordinator','manager') and public.es_subordinado(p_gestor, auth.uid())) );
$$;
revoke execute on function public.ve_cartera(uuid) from public, anon;
grant  execute on function public.ve_cartera(uuid) to authenticated;

-- Contactos: como la cartera, y además Soporte ve los que ya son clientes.
create or replace function public.ve_contacto(p_gestor uuid, p_tipo text)
returns boolean language sql stable security definer set search_path = public as $$
  select public.ve_cartera(p_gestor) or (public.mi_rol() = 'support' and p_tipo = 'cliente');
$$;
revoke execute on function public.ve_contacto(uuid, text) from public, anon;
grant  execute on function public.ve_contacto(uuid, text) to authenticated;

-- =============================================================================
-- 2 · PERMISOS DE FÁBRICA DE CADA ROL
-- =============================================================================
create or replace function public.permisos_de_rol(p_rol public.rol_usuario)
returns jsonb language sql stable as $$
  select coalesce(jsonb_object_agg(c.clave,
    case p_rol
      when 'admin' then true
      when 'coordinator' then c.clave in ('presu.ver','presu.crear','presu.dto','funnel.ver','exp.ver',
             'exp.estado','exp.hitos','exp.docs','hr.ver','hr.mover','hr.contratar',
             'com.llamadas','com.wsp','com.plant','sys.audit',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver','recursos.subir','recursos.borrar',
             'soporte.ver','soporte.gestionar','soporte.escalar')
      when 'manager' then c.clave in ('presu.ver','presu.crear','presu.dto','funnel.ver','exp.ver',
             'exp.estado','exp.hitos','exp.docs','hr.ver','hr.mover','hr.contratar',
             'com.llamadas','com.wsp','com.plant','sys.audit',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver','recursos.subir','recursos.borrar',
             'soporte.ver','soporte.gestionar','soporte.escalar')
      when 'commercial' then c.clave in ('presu.ver','presu.crear','funnel.ver','exp.ver','exp.docs',
             'com.llamadas','com.wsp',
             'contactos.ver','contactos.crea','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs',
             'recursos.ver',
             'soporte.ver')
      when 'backoffice' then c.clave in ('exp.ver','exp.estado','exp.hitos','exp.docs','exp.borrar',
             'presu.ver','com.llamadas',
             'contactos.ver','contactos.editar','contactos.notas',
             'contactos.comentar','contactos.docs','contactos.borrar',
             'recursos.ver',
             'soporte.ver')
      when 'support' then c.clave in ('exp.ver','com.llamadas',
             'contactos.ver','contactos.notas','contactos.comentar',
             'recursos.ver',
             'soporte.ver','soporte.gestionar','soporte.escalar')
    end), '{}'::jsonb)
  from public.permisos_catalogo c;
$$;

-- =============================================================================
-- 3 · USUARIOS: privacidad vertical
-- =============================================================================
-- Antes, Administrador y Jefe de Equipo veían el directorio entero. Ahora cada
-- uno ve su ficha y la de quien depende de él; el admin, todas.
drop policy if exists perfiles_lee_admin  on public.perfiles;
drop policy if exists perfiles_lee_linea  on public.perfiles;
create policy perfiles_lee_linea on public.perfiles
  for select using (public.soy_admin() or public.es_subordinado(id, auth.uid()));

-- Bitácora: lo propio y lo de la propia línea; el admin, todo.
drop policy if exists bitacora_lee on public.bitacora;
create policy bitacora_lee on public.bitacora
  for select using (
       public.soy_admin()
    or destino_id = auth.uid() or actor_id = auth.uid()
    or (public.mi_rol() in ('coordinator','manager')
        and (public.es_subordinado(destino_id, auth.uid()) or public.es_subordinado(actor_id, auth.uid()))) );

-- Límites al editar a alguien de la línea: solo los roles asignables, sin
-- tocar permisos sueltos, plantillas, módulos ni correo.
create or replace function public.limita_jefe()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_yo public.perfiles%rowtype;
begin
  if auth.uid() is null or auth.uid() = new.id then return new; end if;
  select * into v_yo from public.perfiles where id = auth.uid();
  if not found or v_yo.raiz or v_yo.rol = 'admin' then return new; end if;

  if new.rol is distinct from old.rol and not (new.rol = any(public.roles_asignables(v_yo.id))) then
    raise exception 'Con tu rol solo puedes asignar: %.', array_to_string(public.roles_asignables(v_yo.id), ', ')
      using errcode = 'insufficient_privilege', hint = 'ROL_NO_PERMITIDO';
  end if;
  if new.email is distinct from old.email then
    raise exception 'El correo solo lo cambia un Administrador.'
      using errcode = 'insufficient_privilege', hint = 'CORREO_SOLO_ADMIN';
  end if;

  new.raiz                 := old.raiz;
  new.modulos_visibles     := old.modulos_visibles;
  new.rol_personalizado_id := old.rol_personalizado_id;
  new.api_token            := old.api_token;
  new.permisos := case when new.rol is distinct from old.rol
                       then public.permisos_de_rol(new.rol) else old.permisos end;
  return new;
end $$;

-- =============================================================================
-- 4 · CONTACTOS
-- =============================================================================
drop policy if exists contactos_lee   on public.contactos;
drop policy if exists contactos_edita on public.contactos;
create policy contactos_lee on public.contactos
  for select using (public.puedo('contactos.ver') and public.ve_contacto(gestor_id, tipo::text));
create policy contactos_edita on public.contactos
  for update using (public.puedo('contactos.editar') and public.ve_cartera(gestor_id))
  with check (public.puedo('contactos.editar') and public.ve_cartera(gestor_id));

drop policy if exists contacto_eventos_lee  on public.contacto_eventos;
drop policy if exists contacto_eventos_crea on public.contacto_eventos;
create policy contacto_eventos_lee on public.contacto_eventos
  for select using (public.puedo('contactos.ver') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_contacto(c.gestor_id, c.tipo::text)));
create policy contacto_eventos_crea on public.contacto_eventos
  for insert with check (autor_id = auth.uid() and public.puedo('contactos.notas') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_contacto(c.gestor_id, c.tipo::text)));

drop policy if exists contacto_comentarios_lee  on public.contacto_comentarios;
drop policy if exists contacto_comentarios_crea on public.contacto_comentarios;
create policy contacto_comentarios_lee on public.contacto_comentarios
  for select using (public.puedo('contactos.ver') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_contacto(c.gestor_id, c.tipo::text)));
create policy contacto_comentarios_crea on public.contacto_comentarios
  for insert with check (autor_id = auth.uid() and public.puedo('contactos.comentar') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_contacto(c.gestor_id, c.tipo::text)));

drop policy if exists contacto_docs_lee   on public.contacto_documentos;
drop policy if exists contacto_docs_crea  on public.contacto_documentos;
drop policy if exists contacto_docs_borra on public.contacto_documentos;
create policy contacto_docs_lee on public.contacto_documentos
  for select using (public.puedo('contactos.ver') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_contacto(c.gestor_id, c.tipo::text)));
create policy contacto_docs_crea on public.contacto_documentos
  for insert with check (subido_por = auth.uid() and public.puedo('contactos.docs') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_cartera(c.gestor_id)));
create policy contacto_docs_borra on public.contacto_documentos
  for delete using (public.puedo('contactos.borrar') and exists (
    select 1 from public.contactos c where c.id = contacto_id and public.ve_cartera(c.gestor_id)));

drop policy if exists contactos_docs_lee_obj   on storage.objects;
drop policy if exists contactos_docs_sube_obj  on storage.objects;
drop policy if exists contactos_docs_borra_obj on storage.objects;
create policy contactos_docs_lee_obj on storage.objects for select using (
  bucket_id = 'documentos' and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.ver')
  and exists (select 1 from public.contactos c
              where c.id::text = (storage.foldername(name))[2]
                and public.ve_contacto(c.gestor_id, c.tipo::text)));
create policy contactos_docs_sube_obj on storage.objects for insert with check (
  bucket_id = 'documentos' and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.docs')
  and exists (select 1 from public.contactos c
              where c.id::text = (storage.foldername(name))[2] and public.ve_cartera(c.gestor_id)));
create policy contactos_docs_borra_obj on storage.objects for delete using (
  bucket_id = 'documentos' and (storage.foldername(name))[1] = 'contactos'
  and public.puedo('contactos.borrar')
  and exists (select 1 from public.contactos c
              where c.id::text = (storage.foldername(name))[2] and public.ve_cartera(c.gestor_id)));

-- =============================================================================
-- 5 · CONTRATOS Y FIRMA
-- =============================================================================
drop policy if exists contratos_lee   on public.contratos;
drop policy if exists contratos_edita on public.contratos;
create policy contratos_lee on public.contratos
  for select using (public.ve_cartera(gestor_id));
create policy contratos_edita on public.contratos
  for update using (public.ve_cartera(gestor_id)) with check (public.ve_cartera(gestor_id));

drop policy if exists firma_eventos_lee on public.firma_eventos;
create policy firma_eventos_lee on public.firma_eventos
  for select using (exists (select 1 from public.contratos c
                            where c.id = contrato_id and public.ve_cartera(c.gestor_id)));

-- Enlace de firma: el gestor del contrato, su línea, Tramitación o el admin.
create or replace function public.nuevo_enlace_firma(p_codigo text, p_dias int default 30)
returns table (token uuid, expira timestamptz)
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_c public.contratos%rowtype; v_tok uuid; v_exp timestamptz;
begin
  if auth.uid() is null then
    raise exception 'Hay que iniciar sesión para emitir un enlace de firma.';
  end if;
  if p_dias is null or p_dias < 1 or p_dias > 90 then p_dias := 30; end if;

  select * into v_c from public.contratos where codigo = p_codigo;
  if not found then
    raise exception 'No existe el contrato %', p_codigo;
  end if;

  -- Solo el gestor del contrato o la dirección pueden emitirlo.
  if not public.ve_cartera(v_c.gestor_id) then
    raise exception 'No tienes permiso sobre el contrato %', p_codigo;
  end if;

  if v_c.estado = 'Firmado' then
    raise exception 'El contrato % ya está firmado.', p_codigo;
  end if;
  if v_c.estado = 'Anulado' then
    raise exception 'El contrato % está anulado.', p_codigo;
  end if;

  v_tok := gen_random_uuid();
  v_exp := now() + (p_dias || ' days')::interval;

  update public.contratos
     set token = v_tok, token_expira = v_exp, token_usado = false,
         estado = case when estado = 'Borrador' then 'Enviado'::public.estado_contrato
                       else estado end,
         enviado_el = coalesce(enviado_el, now())
   where id = v_c.id;

  insert into public.firma_eventos (contrato_id, evento, ip, ua, detalle)
  values (v_c.id, 'emitido', public.ip_peticion(), public.cabecera('user-agent'),
          'Caduca el ' || to_char(v_exp, 'DD/MM/YYYY'));

  return query select v_tok, v_exp;
end $$;

-- =============================================================================
-- 6 · OTROS MÓDULOS QUE MIRABAN EL ROL
-- =============================================================================
-- Mission Control: dirección (ahora también el Coordinador).
drop policy if exists agentes_lee  on public.agentes;
drop policy if exists acciones_lee on public.agente_acciones;
create policy agentes_lee on public.agentes
  for select using (public.mi_rol() in ('admin','coordinator','manager'));
create policy acciones_lee on public.agente_acciones
  for select using (public.mi_rol() in ('admin','coordinator','manager'));

-- Descargas de dosieres: las propias y las de la propia línea.
drop policy if exists recursos_desc_lee on public.recursos_descargas;
create policy recursos_desc_lee on public.recursos_descargas
  for select using (public.soy_admin() or usuario_id = auth.uid()
                    or public.es_subordinado(usuario_id, auth.uid()));

-- Incidencias: el Nivel 1 lo atiende el rol Soporte; si no hay nadie de
-- Soporte activo, un Jefe de Equipo, como hasta ahora.
create or replace function public.asigna_ticket_auto()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if new.prioridad in ('alta','critica') then
    new.nivel_escalado := greatest(new.nivel_escalado, 1);
    if new.asignado_a is null then
      new.asignado_a := coalesce(public.elige_responsable_ticket('support'),
                                 public.elige_responsable_ticket('manager'));
    end if;
  end if;
  return new;
end;
$$;

-- =============================================================================
-- 7 · ALTA DE USUARIOS CON LOS ROLES NUEVOS
-- =============================================================================
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

  v_permitidos := coalesce(public.roles_asignables(v_yo.id), array[]::public.rol_usuario[]);

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

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from pg_proc where proname in
     ('rango','es_subordinado','roles_asignables','gestiono','dirijo_agente','ve_cartera','ve_contacto')) as funciones,
  (select count(*) from pg_policies where policyname in
     ('perfiles_lee_linea','bitacora_lee','contactos_lee','contratos_lee')) as politicas,
  (select string_agg(nombre || ' (' || case when raiz then 'Superadmin' else rol::text end || ')', ', '
                     order by public.rango(rol, raiz) desc, nombre)
     from public.perfiles) as usuarios;
-- Esperado: funciones = 7, politicas = 4 y la lista de usuarios con su rol.
