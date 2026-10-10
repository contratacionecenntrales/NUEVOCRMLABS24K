-- =============================================================================
-- LABS COMMAND CENTER 360™ · Firma del contrato por el cliente
-- Ejecutar DESPUÉS de 04-mission-contratos.sql
--
-- Permite enviar al cliente un enlace de un solo uso (firmar.html#t=...) para
-- que revise el contrato, complete sus datos y lo firme desde el móvil.
--
-- CÓMO ESTÁ PLANTEADA LA SEGURIDAD
--   · El cliente NO tiene cuenta. Entra como «anon», con la clave publicable.
--   · La tabla `contratos` sigue cerrada a «anon»: no hay ninguna política que
--     le deje leerla ni escribirla.
--   · Lo único que puede hacer son las tres funciones de abajo, que son
--     SECURITY DEFINER y solo devuelven los campos del contrato de SU token.
--     Sin token válido, no hay nada que ver.
--   · El token lo genera Postgres (gen_random_uuid), no el navegador, y caduca.
--
-- QUÉ VALOR TIENE ESTA FIRMA
--   Es una FIRMA ELECTRÓNICA SIMPLE (art. 3.10 del Reglamento eIDAS). Es válida
--   y admisible como prueba, pero si el cliente la niega, la carga de probar
--   que firmó es vuestra. Por eso se guardan la fecha, la hora, la IP, el
--   agente de usuario y una huella SHA-256 del texto exacto que aceptó: son las
--   evidencias con las que se sostiene. Para contratos de importe alto,
--   utilizad un prestador cualificado (Signaturit, Firmafy, Uanataca...).
-- =============================================================================

-- =============================================================================
-- 1 · COLUMNAS DE FIRMA
-- =============================================================================
alter table public.contratos
  add column if not exists token          uuid,
  add column if not exists token_expira   timestamptz,
  add column if not exists token_usado    boolean not null default false,
  add column if not exists firma_img      text,
  add column if not exists firma_nombre   text,
  add column if not exists firma_dni      text,
  add column if not exists firma_ip       text,
  add column if not exists firma_ua       text,
  add column if not exists firma_huella   text,
  add column if not exists firmado_ts     timestamptz,
  -- Los huecos del documento que no tienen columna propia (ciudad, IBAN, plazo,
  -- referencia del presupuesto, Anexo I) viajan aquí, para no añadir una columna
  -- por cada corchete del contrato.
  add column if not exists datos_contrato jsonb not null default '{}'::jsonb;

create unique index if not exists contratos_token_idx
  on public.contratos(token) where token is not null;

comment on column public.contratos.firma_img is
  'Trazo de la firma en PNG (data URI). Es un dato personal: no lo saques de aquí sin motivo.';
comment on column public.contratos.firma_huella is
  'SHA-256 del texto que el cliente tenía delante al firmar. Si alguien discute qué firmó, esto lo resuelve.';

-- Registro de lo que ocurre con cada enlace. Solo se añade, nunca se corrige:
-- un rastro que se puede editar no sirve como prueba.
create table if not exists public.firma_eventos (
  id           bigserial primary key,
  contrato_id  bigint references public.contratos(id) on delete cascade,
  ts           timestamptz not null default now(),
  evento       text not null check (evento in ('emitido','abierto','firmado','rechazado','caducado')),
  ip           text,
  ua           text,
  detalle      text not null default ''
);
create index if not exists firma_eventos_idx on public.firma_eventos(contrato_id, ts desc);

-- =============================================================================
-- 2 · DE DÓNDE SALEN LA IP Y EL NAVEGADOR
-- PostgREST publica las cabeceras de la petición en `request.headers`.
-- =============================================================================
create or replace function public.cabecera(p_nombre text)
returns text language plpgsql stable security definer set search_path = public, pg_temp as $$
declare v_h json;
begin
  begin
    v_h := current_setting('request.headers', true)::json;
  exception when others then
    return null;
  end;
  if v_h is null then return null; end if;
  return v_h ->> p_nombre;
end $$;

create or replace function public.ip_peticion()
returns text language sql stable security definer set search_path = public, pg_temp as $$
  -- x-forwarded-for puede traer varias IP separadas por coma; la primera es la del cliente.
  select coalesce(split_part(public.cabecera('x-forwarded-for'), ',', 1),
                  public.cabecera('x-real-ip'));
$$;

-- =============================================================================
-- 3 · EMITIR UN ENLACE  (lo llama el panel, con sesión iniciada)
-- =============================================================================
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
  if not (public.mi_rol() in ('admin','manager','backoffice') or v_c.gestor_id = auth.uid()) then
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

revoke all on function public.nuevo_enlace_firma(text, int) from public, anon;
grant execute on function public.nuevo_enlace_firma(text, int) to authenticated;

-- =============================================================================
-- 4 · LEER EL CONTRATO CON EL TOKEN  (lo llama el cliente, sin cuenta)
-- Devuelve SOLO lo que hace falta para pintar el contrato. Ni el gestor, ni el
-- expediente, ni el resto de la cartera.
-- =============================================================================
create or replace function public.contrato_para_firma(p_token uuid)
returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_c public.contratos%rowtype;
begin
  if p_token is null then
    return jsonb_build_object('error', 'sin-token');
  end if;

  select * into v_c from public.contratos where token = p_token;
  if not found then
    return jsonb_build_object('error', 'no-existe');
  end if;

  insert into public.firma_eventos (contrato_id, evento, ip, ua)
  values (v_c.id, 'abierto', public.ip_peticion(), public.cabecera('user-agent'));

  if v_c.token_usado or v_c.estado = 'Firmado' then
    return jsonb_build_object('error', 'ya-firmado',
      'firmado_ts', v_c.firmado_ts, 'cliente', v_c.cliente);
  end if;
  if v_c.token_expira is not null and v_c.token_expira < now() then
    return jsonb_build_object('error', 'caducado', 'expira', v_c.token_expira);
  end if;
  if v_c.estado = 'Anulado' then
    return jsonb_build_object('error', 'anulado');
  end if;

  return jsonb_build_object(
    'codigo',   v_c.codigo,
    'expira',   v_c.token_expira,
    'cliente',  v_c.cliente,
    'cif',      v_c.cif,
    'dir',      v_c.domicilio,
    'rep',      v_c.representante,
    'mail',     v_c.email,
    'tel',      v_c.telefono,
    'servicio', v_c.servicio,
    'base',     v_c.setup,
    'mensual',  v_c.mensual,
    'iva',      v_c.iva,
    'fecha',    v_c.inicio,
    'datos',    coalesce(v_c.datos_contrato, '{}'::jsonb)
  );
end $$;

revoke all on function public.contrato_para_firma(uuid) from public;
grant execute on function public.contrato_para_firma(uuid) to anon, authenticated;

-- =============================================================================
-- 5 · FIRMAR  (lo llama el cliente, sin cuenta)
-- =============================================================================
create or replace function public.firma_contrato(
  p_token   uuid,
  p_nombre  text,
  p_dni     text,
  p_firma   text,          -- PNG en data URI
  p_huella  text default null,
  p_datos   jsonb default '{}'::jsonb
) returns jsonb
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_c public.contratos%rowtype;
begin
  select * into v_c from public.contratos where token = p_token;
  if not found then return jsonb_build_object('error','no-existe'); end if;
  if v_c.token_usado or v_c.estado = 'Firmado' then
    return jsonb_build_object('error','ya-firmado'); end if;
  if v_c.token_expira is not null and v_c.token_expira < now() then
    return jsonb_build_object('error','caducado'); end if;
  if v_c.estado = 'Anulado' then return jsonb_build_object('error','anulado'); end if;

  -- Validaciones. Son cortas a propósito: aquí no se limpia HTML porque nada de
  -- esto se vuelve a inyectar como HTML sin escapar.
  if p_nombre is null or length(trim(p_nombre)) < 3 then
    return jsonb_build_object('error','falta-nombre'); end if;
  if p_dni is null or length(trim(p_dni)) < 8 then
    return jsonb_build_object('error','falta-dni'); end if;
  if p_firma is null or p_firma !~ '^data:image/png;base64,' then
    return jsonb_build_object('error','falta-firma'); end if;
  if length(p_firma) > 400000 then                     -- ~300 KB de PNG
    return jsonb_build_object('error','firma-demasiado-grande'); end if;

  update public.contratos
     set estado       = 'Firmado',
         firma_img    = p_firma,
         firma_nombre = trim(p_nombre),
         firma_dni    = upper(trim(p_dni)),
         firma_ip     = public.ip_peticion(),
         firma_ua     = public.cabecera('user-agent'),
         firma_huella = p_huella,
         firmado_ts   = now(),
         firmado_el   = current_date,
         representante = coalesce(nullif(trim(p_nombre), ''), representante),
         datos_contrato = datos_contrato || coalesce(p_datos, '{}'::jsonb),
         token_usado  = true
   where id = v_c.id;

  insert into public.firma_eventos (contrato_id, evento, ip, ua, detalle)
  values (v_c.id, 'firmado', public.ip_peticion(), public.cabecera('user-agent'),
          'Firmado por ' || trim(p_nombre));

  return jsonb_build_object('ok', true, 'codigo', v_c.codigo, 'ts', now());
end $$;

revoke all on function public.firma_contrato(uuid, text, text, text, text, jsonb) from public;
grant execute on function public.firma_contrato(uuid, text, text, text, text, jsonb) to anon, authenticated;

-- =============================================================================
-- 6 · RLS DE LOS EVENTOS
-- Las escriben las funciones (que son SECURITY DEFINER y se saltan RLS). Aquí
-- solo se decide quién puede LEERLAS desde el panel.
-- =============================================================================
alter table public.firma_eventos enable row level security;

drop policy if exists firma_eventos_lee on public.firma_eventos;
create policy firma_eventos_lee on public.firma_eventos
  for select using (
    public.mi_rol() in ('admin','manager','backoffice')
    or exists (select 1 from public.contratos c
                where c.id = contrato_id and c.gestor_id = auth.uid())
  );
-- Sin INSERT, UPDATE ni DELETE para nadie: el rastro no se toca desde el panel.

grant select on public.firma_eventos to authenticated;

-- «anon» no gana acceso a ninguna tabla: solo a las dos funciones de arriba.
revoke all on public.contratos     from anon;
revoke all on public.firma_eventos from anon;

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from information_schema.columns
    where table_schema='public' and table_name='contratos'
      and column_name in ('token','firma_img','firma_huella','datos_contrato')) as columnas_firma,
  (select count(*) from pg_proc p join pg_namespace n on n.oid=p.pronamespace
    where n.nspname='public'
      and p.proname in ('nuevo_enlace_firma','contrato_para_firma','firma_contrato')) as funciones,
  (select count(*) from pg_policies
    where schemaname='public' and tablename='firma_eventos') as politicas;
