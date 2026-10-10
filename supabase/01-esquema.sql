-- =============================================================================
-- LABS COMMAND CENTER 360™ · Esquema de Supabase
-- Labs24k · Grupo Evolvix Global SL
--
-- CÓMO SE EJECUTA
--   Panel de Supabase → SQL Editor → New query → pegar todo → Run.
--   Es idempotente: se puede volver a lanzar sin romper nada.
--
-- QUÉ CREA
--   perfiles        · la ficha de cada usuario, atada a auth.users
--   bitacora        · auditoría de solo-añadir (sin UPDATE ni DELETE)
--   accesos_raiz    · registro forense de la cuenta de raíz
--   sesiones        · dispositivos con sesión abierta
--   expedientes     · clientes activos, con su bitácora y documentos
--   candidatos      · pipeline de selección
--   presupuestos    · propuestas emitidas
--
-- LO IMPORTANTE
--   Todas las tablas llevan RLS activada. La clave publicable que va en el
--   navegador NO otorga permisos por sí sola: cada consulta se filtra por el
--   rol del usuario que ha iniciado sesión. Sin sesión válida no se ve nada.
-- =============================================================================

create extension if not exists "pgcrypto" with schema extensions;

-- =============================================================================
-- 1 · TIPOS
-- =============================================================================
do $$ begin
  create type public.rol_usuario as enum ('admin', 'manager', 'commercial', 'backoffice');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.estado_cuenta as enum ('Activo', 'Suspendido', 'Dado de baja');
exception when duplicate_object then null; end $$;

-- =============================================================================
-- 2 · PERFILES
-- La contraseña NO está aquí: la guarda Supabase Auth en auth.users, cifrada.
-- Esta tabla es la ficha de empresa que cuelga de esa identidad.
-- =============================================================================
create table if not exists public.perfiles (
  id            uuid primary key references auth.users(id) on delete cascade,
  raiz          boolean not null default false,
  nombre        text not null check (length(trim(nombre)) between 2 and 60),
  apellidos     text not null default '',
  email         text not null unique,
  prefijo       text not null default '+34' check (prefijo ~ '^\+\d{1,3}$'),
  telefono      text not null default '',
  extension     text not null default '' check (extension ~ '^\d{0,6}$'),
  rol           public.rol_usuario  not null default 'commercial',
  estado        public.estado_cuenta not null default 'Activo',
  rel           text not null unique,
  avatar_url    text,
  google        boolean not null default false,
  doble_factor  boolean not null default false,
  debe_cambiar  boolean not null default true,
  permisos      jsonb   not null default '{}'::jsonb,
  preferencias  jsonb   not null default '{}'::jsonb,
  api_token     text,
  alta          date    not null default current_date,
  ultimo_acceso timestamptz,
  creado        timestamptz not null default now(),
  actualizado   timestamptz not null default now()
);

comment on table  public.perfiles is 'Ficha corporativa de cada usuario. La identidad y la contraseña viven en auth.users.';
comment on column public.perfiles.raiz is 'Super Administrador de raíz: cuenta única, permanente y con todos los permisos.';
comment on column public.perfiles.permisos is 'Matriz granular {clave: booleano}. Parte de los permisos del rol y admite excepciones.';

create index if not exists perfiles_rol_idx    on public.perfiles(rol);
create index if not exists perfiles_estado_idx on public.perfiles(estado);
create index if not exists perfiles_email_idx  on public.perfiles(lower(email));

-- =============================================================================
-- 3 · CATÁLOGO DE PERMISOS Y VALORES POR ROL
-- En la base de datos para que panel y API no puedan discrepar nunca.
-- =============================================================================
create table if not exists public.permisos_catalogo (
  clave       text primary key,
  grupo       text not null,
  nombre      text not null,
  descripcion text not null default '',
  orden       int  not null default 0
);

insert into public.permisos_catalogo (clave, grupo, nombre, descripcion, orden) values
  ('presu.ver',    'Comercial',            'Ver presupuestos',            'Consultar el histórico de propuestas', 10),
  ('presu.crear',  'Comercial',            'Crear y enviar propuestas',   'Generar documentos con el catálogo oficial', 20),
  ('presu.dto',    'Comercial',            'Aplicar descuentos',          'Modificar el precio de tarifa', 30),
  ('funnel.ver',   'Comercial',            'Ver embudos de venta',        'Acceso a la evolución del pipeline', 40),
  ('exp.ver',      'Clientes y expedientes','Ver expedientes',            'Ficha completa del cliente activo', 50),
  ('exp.estado',   'Clientes y expedientes','Cambiar el estado',          'Avanzar la fase de implantación', 60),
  ('exp.hitos',    'Clientes y expedientes','Marcar hitos',               'Validar los pasos de la hoja de ruta', 70),
  ('exp.docs',     'Clientes y expedientes','Subir documentación',        'Contratos, auditorías y anexos', 80),
  ('exp.borrar',   'Clientes y expedientes','Eliminar registros',         'Borrado de documentos y expedientes', 90),
  ('hr.ver',       'Talento y equipo',     'Ver el pipeline de selección','Candidatos y entrevistas', 100),
  ('hr.mover',     'Talento y equipo',     'Mover candidatos de fase',    'Gestionar el proceso de selección', 110),
  ('hr.contratar', 'Talento y equipo',     'Cerrar contrataciones',       'Dar por incorporado a un candidato', 120),
  ('com.llamadas', 'Comunicaciones',       'Centralita y llamadas',       'Marcador, grabaciones y buzón', 130),
  ('com.wsp',      'Comunicaciones',       'WhatsApp y voz IA',           'Agentes automáticos de conversación', 140),
  ('com.plant',    'Comunicaciones',       'Editar plantillas',           'Mensajes tipo de la red comercial', 150),
  ('sys.config',   'Sistema',              'Configuración global',        'Marca, precios, enlaces y claves', 160),
  ('sys.usuarios', 'Sistema',              'Gestión de usuarios',         'Altas, bajas y permisos', 170),
  ('sys.audit',    'Sistema',              'Bitácora de auditoría',       'Ver quién ha cambiado qué', 180)
on conflict (clave) do update
  set grupo = excluded.grupo, nombre = excluded.nombre,
      descripcion = excluded.descripcion, orden = excluded.orden;

create or replace function public.permisos_de_rol(p_rol public.rol_usuario)
returns jsonb language sql stable as $$
  select coalesce(jsonb_object_agg(c.clave,
    case p_rol
      when 'admin' then true
      when 'manager' then c.clave in ('presu.ver','presu.crear','presu.dto','funnel.ver','exp.ver',
             'exp.estado','exp.hitos','exp.docs','hr.ver','hr.mover','hr.contratar',
             'com.llamadas','com.wsp','com.plant','sys.audit')
      when 'commercial' then c.clave in ('presu.ver','presu.crear','funnel.ver','exp.ver','exp.docs',
             'com.llamadas','com.wsp')
      when 'backoffice' then c.clave in ('exp.ver','exp.estado','exp.hitos','exp.docs','exp.borrar',
             'presu.ver','com.llamadas')
    end), '{}'::jsonb)
  from public.permisos_catalogo c;
$$;

-- =============================================================================
-- 4 · AYUDANTES DE SEGURIDAD
-- SECURITY DEFINER para poder leer perfiles desde dentro de las políticas sin
-- caer en recursión infinita de RLS. search_path fijado: sin él, un esquema
-- creado por un atacante podría suplantar a estas funciones.
-- =============================================================================
create or replace function public.mi_rol()
returns public.rol_usuario language sql stable security definer set search_path = public as $$
  select rol from public.perfiles where id = auth.uid() and estado = 'Activo';
$$;

create or replace function public.soy_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.perfiles
                 where id = auth.uid() and rol = 'admin' and estado = 'Activo');
$$;

create or replace function public.puedo(p_clave text)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce((select (permisos ->> p_clave)::boolean from public.perfiles
                   where id = auth.uid() and estado = 'Activo'), false);
$$;

-- =============================================================================
-- 5 · BLINDAJE DE LA CUENTA DE RAÍZ
-- Un disparador, no una comprobación de la aplicación: da igual desde dónde
-- llegue la orden —panel, API, consola SQL o la propia clave de servicio—,
-- la base de datos se niega igual.
-- =============================================================================
create or replace function public.protege_raiz()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if (tg_op = 'DELETE') then
    if old.raiz then
      raise exception 'El Super Administrador de raíz no se puede eliminar.'
        using errcode = 'check_violation', hint = 'RAIZ_INDESTRUCTIBLE';
    end if;
    return old;
  end if;

  if (tg_op = 'UPDATE' and old.raiz) then
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
    -- Permisos y doble factor se reimponen en silencio, no se rechaza la orden.
    new.permisos     := public.permisos_de_rol('admin');
    new.doble_factor := true;
  end if;

  -- Solo puede existir una cuenta de raíz.
  if (new.raiz and exists (select 1 from public.perfiles
                           where raiz and id <> new.id)) then
    raise exception 'Ya existe un Super Administrador de raíz.'
      using errcode = 'unique_violation', hint = 'RAIZ_UNICA';
  end if;

  -- Ser raíz implica ser administradora y estar activa, SIEMPRE: también en el
  -- momento en que se pone la marca, no solo después.
  --
  -- Sin esto quedaba un hueco: el bloque de arriba solo vigila los perfiles que
  -- YA eran raíz (old.raiz), así que marcar como raíz a un comercial pasaba el
  -- control y dejaba una cuenta raíz sin permisos de administración —imposible
  -- de arreglar después, porque a partir de entonces el propio disparador
  -- rechaza cambiarle el rol. En la práctica la comprobación de unicidad lo
  -- tapaba, pero taparlo no es cerrarlo.
  if new.raiz then
    new.rol          := 'admin';
    new.estado       := 'Activo';
    new.permisos     := public.permisos_de_rol('admin');
    new.doble_factor := true;
  end if;

  new.actualizado := now();
  return new;
end $$;

drop trigger if exists perfiles_protege_raiz on public.perfiles;
create trigger perfiles_protege_raiz
  before update or delete on public.perfiles
  for each row execute function public.protege_raiz();

drop trigger if exists perfiles_raiz_unica on public.perfiles;
create trigger perfiles_raiz_unica
  before insert on public.perfiles
  for each row execute function public.protege_raiz();

-- Nadie se sube a sí mismo de rango: ni rol, ni estado, ni permisos propios.
create or replace function public.impide_autoescalada()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and auth.uid() = new.id then
    if new.rol is distinct from old.rol
       or new.estado is distinct from old.estado
       or new.permisos is distinct from old.permisos then
      raise exception 'No puedes cambiar tu propio rol, estado ni permisos.'
        using errcode = 'insufficient_privilege', hint = 'AUTO_ESCALADA';
    end if;
  end if;
  return new;
end $$;

drop trigger if exists perfiles_sin_autoescalada on public.perfiles;
create trigger perfiles_sin_autoescalada
  before update on public.perfiles
  for each row execute function public.impide_autoescalada();

-- El sistema nunca se queda sin administrador activo.
create or replace function public.exige_un_admin()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from public.perfiles where rol = 'admin' and estado = 'Activo') then
    raise exception 'No puedes dejar el sistema sin ningún administrador activo.'
      using errcode = 'check_violation', hint = 'ULTIMO_ADMIN';
  end if;
  return null;
end $$;

drop trigger if exists perfiles_un_admin on public.perfiles;
create constraint trigger perfiles_un_admin
  after update or delete on public.perfiles
  deferrable initially deferred
  for each row execute function public.exige_un_admin();

-- =============================================================================
-- 6 · BITÁCORA DE AUDITORÍA · solo se añade
-- =============================================================================
create table if not exists public.bitacora (
  id             uuid primary key default gen_random_uuid(),
  ts             timestamptz not null default now(),
  actor_id       uuid references public.perfiles(id) on delete set null,
  actor_nombre   text not null default 'sistema',
  actor_rol      text,
  destino_id     uuid,
  destino_nombre text,
  accion         text not null,
  detalle        text not null default '',
  ip             text,
  agente         text
);
create index if not exists bitacora_ts_idx      on public.bitacora(ts desc);
create index if not exists bitacora_destino_idx on public.bitacora(destino_id);

comment on table public.bitacora is
  'Auditoría de solo-añadir: no existe política de UPDATE ni de DELETE, así que ni el propio administrador puede reescribir el pasado desde la aplicación.';

-- Cada cambio en una ficha se anota solo, sin depender de que la aplicación
-- se acuerde de hacerlo.
create or replace function public.anota_cambio_perfil()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_actor  public.perfiles%rowtype;
  v_partes text[] := '{}';
  v_accion text;
begin
  select * into v_actor from public.perfiles where id = auth.uid();

  if tg_op = 'INSERT' then
    v_accion := 'Cuenta creada';
    v_partes := array[new.rol::text || ' · relación ' || new.rel];
  elsif tg_op = 'DELETE' then
    v_accion := 'Cuenta eliminada';
    v_partes := array['relación ' || old.rel || ' · ' || old.rol::text];
  else
    v_accion := 'Ficha actualizada';
    if new.nombre    is distinct from old.nombre
    or new.apellidos is distinct from old.apellidos then v_partes := array_append(v_partes, 'nombre'); end if;
    if new.email     is distinct from old.email     then v_partes := array_append(v_partes, 'correo'); end if;
    if new.rol       is distinct from old.rol       then v_partes := array_append(v_partes, 'rol → ' || new.rol::text); end if;
    if new.estado    is distinct from old.estado    then v_partes := array_append(v_partes, 'estado → ' || new.estado::text); end if;
    if new.google    is distinct from old.google    then
      v_partes := array_append(v_partes,
        case when new.google then 'Google autorizado' else 'Google revocado' end); end if;
    if new.permisos  is distinct from old.permisos  then v_partes := array_append(v_partes, 'permisos'); end if;
    if new.api_token is distinct from old.api_token then v_partes := array_append(v_partes, 'token de API rotado'); end if;
    if new.avatar_url is distinct from old.avatar_url then v_partes := array_append(v_partes, 'foto de perfil'); end if;
    if array_length(v_partes, 1) is null then return new; end if;   -- nada reseñable
  end if;

  insert into public.bitacora (actor_id, actor_nombre, actor_rol, destino_id, destino_nombre,
                               accion, detalle)
  values (auth.uid(),
          coalesce(trim(v_actor.nombre || ' ' || v_actor.apellidos), 'sistema'),
          v_actor.rol::text,
          coalesce(new.id, old.id),
          trim(coalesce(new.nombre, old.nombre) || ' ' || coalesce(new.apellidos, old.apellidos)),
          v_accion, array_to_string(v_partes, ', '));
  return coalesce(new, old);
end $$;

drop trigger if exists perfiles_anota on public.perfiles;
create trigger perfiles_anota
  after insert or update or delete on public.perfiles
  for each row execute function public.anota_cambio_perfil();

-- =============================================================================
-- 7 · REGISTRO FORENSE DE LA CUENTA DE RAÍZ
-- =============================================================================
create table if not exists public.accesos_raiz (
  id      uuid primary key default gen_random_uuid(),
  ts      timestamptz not null default now(),
  evento  text not null check (evento in ('ENTRADA','ENTRADA_GOOGLE','SALIDA','FALLIDO')),
  usuario uuid,
  email   text,
  ip      text,
  agente  text,
  motivo  text
);
create index if not exists accesos_raiz_ts_idx on public.accesos_raiz(ts desc);

-- =============================================================================
-- 8 · SESIONES ABIERTAS
-- =============================================================================
create table if not exists public.sesiones (
  id          uuid primary key default gen_random_uuid(),
  usuario_id  uuid not null references public.perfiles(id) on delete cascade,
  dispositivo text not null default '',
  ip          text,
  ubicacion   text,
  inicio      timestamptz not null default now(),
  visto       timestamptz not null default now()
);
create index if not exists sesiones_usuario_idx on public.sesiones(usuario_id);

-- =============================================================================
-- 9 · NEGOCIO: expedientes, candidatos y presupuestos
-- =============================================================================
create table if not exists public.expedientes (
  id         bigserial primary key,
  empresa    text not null,
  sector     text not null default '',
  contacto   text not null default '',
  telefono   text not null default '',
  email      text not null default '',
  mrr        numeric(10,2) not null default 0,
  estado     text not null default 'Auditoría inicial',
  hito       int  not null default 0 check (hito between 0 and 5),
  satisfaccion int check (satisfaccion between 0 and 100),
  gestor_id  uuid references public.perfiles(id) on delete set null,
  backoffice_id uuid references public.perfiles(id) on delete set null,
  alta       date not null default current_date,
  creado     timestamptz not null default now(),
  actualizado timestamptz not null default now()
);
create index if not exists expedientes_gestor_idx on public.expedientes(gestor_id);

create table if not exists public.expediente_log (
  id            bigserial primary key,
  expediente_id bigint not null references public.expedientes(id) on delete cascade,
  autor_id      uuid references public.perfiles(id) on delete set null,
  autor_nombre  text not null default '',
  autor_rol     text,
  tipo          text not null default 'avance',
  texto         text not null,
  ts            timestamptz not null default now()
);
create index if not exists expediente_log_exp_idx on public.expediente_log(expediente_id, ts desc);

create table if not exists public.expediente_docs (
  id            bigserial primary key,
  expediente_id bigint not null references public.expedientes(id) on delete cascade,
  nombre        text not null,
  tipo          text not null default '',
  ruta          text,
  subido_por    uuid references public.perfiles(id) on delete set null,
  ts            timestamptz not null default now()
);

create table if not exists public.candidatos (
  id        bigserial primary key,
  nombre    text not null,
  puesto    text not null default '',
  email     text not null default '',
  telefono  text not null default '',
  fase      text not null default 'Solicitud recibida',
  nota      int check (nota between 0 and 10),
  origen    text not null default '',
  responsable_id uuid references public.perfiles(id) on delete set null,
  creado    timestamptz not null default now(),
  actualizado timestamptz not null default now()
);

create table if not exists public.presupuestos (
  id         bigserial primary key,
  codigo     text not null unique,
  cliente    text not null,
  expediente_id bigint references public.expedientes(id) on delete set null,
  autor_id   uuid references public.perfiles(id) on delete set null,
  lineas     jsonb not null default '[]'::jsonb,
  base       numeric(10,2) not null default 0,
  iva        numeric(5,2)  not null default 21,
  total      numeric(10,2) not null default 0,
  estado     text not null default 'Borrador',
  creado     timestamptz not null default now()
);

-- =============================================================================
-- 10 · RLS · aquí está la seguridad de verdad
-- La clave publicable del navegador no da acceso a nada por sí sola: cada fila
-- se comprueba contra el rol del usuario con sesión iniciada.
-- =============================================================================
alter table public.perfiles          enable row level security;
alter table public.permisos_catalogo enable row level security;
alter table public.bitacora          enable row level security;
alter table public.accesos_raiz      enable row level security;
alter table public.sesiones          enable row level security;
alter table public.expedientes       enable row level security;
alter table public.expediente_log    enable row level security;
alter table public.expediente_docs   enable row level security;
alter table public.candidatos        enable row level security;
alter table public.presupuestos      enable row level security;

-- --- perfiles -----------------------------------------------------------
drop policy if exists perfiles_lee_propio   on public.perfiles;
drop policy if exists perfiles_lee_admin    on public.perfiles;
drop policy if exists perfiles_edita_propio on public.perfiles;
drop policy if exists perfiles_admin_todo   on public.perfiles;
drop policy if exists perfiles_admin_borra  on public.perfiles;

create policy perfiles_lee_propio on public.perfiles
  for select using (id = auth.uid());

-- Dirección y Back Office ven el directorio; el resto, solo su propia ficha.
create policy perfiles_lee_admin on public.perfiles
  for select using (public.mi_rol() in ('admin', 'manager'));

-- Cada uno edita SUS datos de contacto. El trigger impide que se toque el rol.
create policy perfiles_edita_propio on public.perfiles
  for update using (id = auth.uid()) with check (id = auth.uid());

create policy perfiles_admin_todo on public.perfiles
  for update using (public.soy_admin()) with check (public.soy_admin());

create policy perfiles_admin_borra on public.perfiles
  for delete using (public.soy_admin());

-- No hay política de INSERT a propósito: las altas las hace la Edge Function
-- con la clave de servicio, que es la única forma de crear también la
-- identidad en auth.users. Nadie se da de alta por su cuenta.

-- --- catálogo de permisos: lectura para cualquiera con sesión -------------
drop policy if exists permisos_lee on public.permisos_catalogo;
create policy permisos_lee on public.permisos_catalogo
  for select using (auth.uid() is not null);

-- --- bitácora: se lee según rol, y NO se modifica -------------------------
drop policy if exists bitacora_lee    on public.bitacora;
drop policy if exists bitacora_inserta on public.bitacora;
create policy bitacora_lee on public.bitacora
  for select using (public.mi_rol() in ('admin','manager') or destino_id = auth.uid());
create policy bitacora_inserta on public.bitacora
  for insert with check (auth.uid() is not null);
-- Sin políticas de UPDATE ni DELETE: con RLS activada, eso significa que la
-- operación se deniega siempre. La bitácora no se reescribe.

-- --- accesos de raíz -----------------------------------------------------
drop policy if exists accesos_raiz_lee     on public.accesos_raiz;
drop policy if exists accesos_raiz_inserta on public.accesos_raiz;
create policy accesos_raiz_lee on public.accesos_raiz
  for select using (public.soy_admin());
create policy accesos_raiz_inserta on public.accesos_raiz
  for insert with check (auth.uid() is not null);

-- --- sesiones ------------------------------------------------------------
drop policy if exists sesiones_lee    on public.sesiones;
drop policy if exists sesiones_crea   on public.sesiones;
drop policy if exists sesiones_borra  on public.sesiones;
create policy sesiones_lee on public.sesiones
  for select using (usuario_id = auth.uid() or public.soy_admin());
create policy sesiones_crea on public.sesiones
  for insert with check (usuario_id = auth.uid());
create policy sesiones_borra on public.sesiones
  for delete using (usuario_id = auth.uid() or public.soy_admin());

-- --- expedientes ---------------------------------------------------------
drop policy if exists exp_lee     on public.expedientes;
drop policy if exists exp_crea    on public.expedientes;
drop policy if exists exp_edita   on public.expedientes;
drop policy if exists exp_borra   on public.expedientes;
create policy exp_lee on public.expedientes
  for select using (public.puedo('exp.ver'));
create policy exp_crea on public.expedientes
  for insert with check (public.puedo('exp.ver'));
create policy exp_edita on public.expedientes
  for update using (public.puedo('exp.estado') or public.puedo('exp.hitos'))
  with check (public.puedo('exp.estado') or public.puedo('exp.hitos'));
create policy exp_borra on public.expedientes
  for delete using (public.puedo('exp.borrar'));

drop policy if exists explog_lee  on public.expediente_log;
drop policy if exists explog_crea on public.expediente_log;
create policy explog_lee on public.expediente_log
  for select using (public.puedo('exp.ver'));
create policy explog_crea on public.expediente_log
  for insert with check (public.puedo('exp.ver') and autor_id = auth.uid());

drop policy if exists expdoc_lee   on public.expediente_docs;
drop policy if exists expdoc_crea  on public.expediente_docs;
drop policy if exists expdoc_borra on public.expediente_docs;
create policy expdoc_lee on public.expediente_docs
  for select using (public.puedo('exp.ver'));
create policy expdoc_crea on public.expediente_docs
  for insert with check (public.puedo('exp.docs'));
create policy expdoc_borra on public.expediente_docs
  for delete using (public.puedo('exp.borrar'));

-- --- candidatos ----------------------------------------------------------
drop policy if exists cand_lee   on public.candidatos;
drop policy if exists cand_crea  on public.candidatos;
drop policy if exists cand_edita on public.candidatos;
create policy cand_lee on public.candidatos
  for select using (public.puedo('hr.ver'));
create policy cand_crea on public.candidatos
  for insert with check (public.puedo('hr.mover'));
create policy cand_edita on public.candidatos
  for update using (public.puedo('hr.mover')) with check (public.puedo('hr.mover'));

-- --- presupuestos --------------------------------------------------------
drop policy if exists presu_lee   on public.presupuestos;
drop policy if exists presu_crea  on public.presupuestos;
drop policy if exists presu_edita on public.presupuestos;
create policy presu_lee on public.presupuestos
  for select using (public.puedo('presu.ver'));
create policy presu_crea on public.presupuestos
  for insert with check (public.puedo('presu.crear') and autor_id = auth.uid());
create policy presu_edita on public.presupuestos
  for update using (public.puedo('presu.crear') and autor_id = auth.uid())
  with check (public.puedo('presu.crear'));

-- =============================================================================
-- 11 · MARCA DE ACTUALIZACIÓN
-- =============================================================================
create or replace function public.marca_actualizado()
returns trigger language plpgsql as $$
begin new.actualizado := now(); return new; end $$;

drop trigger if exists expedientes_actualizado on public.expedientes;
create trigger expedientes_actualizado before update on public.expedientes
  for each row execute function public.marca_actualizado();

drop trigger if exists candidatos_actualizado on public.candidatos;
create trigger candidatos_actualizado before update on public.candidatos
  for each row execute function public.marca_actualizado();

-- =============================================================================
-- 12 · PERMISOS DE ESQUEMA
-- anon (visitante sin sesión) no recibe nada. authenticated trabaja siempre
-- filtrado por las políticas de arriba.
-- =============================================================================
grant usage on schema public to anon, authenticated;
revoke all on all tables in schema public from anon;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- Fin del esquema. Continúa con 02-cuenta-raiz.sql
