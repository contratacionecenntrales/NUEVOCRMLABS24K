-- =============================================================================
-- LABS COMMAND CENTER 360™ · Agentes, contratos y ranking
-- Ejecutar DESPUÉS de 01-esquema.sql
--
-- Añade lo que necesitan las secciones nuevas:
--   agentes            · el panel de Mission Control
--   agente_acciones    · lo que cada agente ha hecho de verdad
--   contratos          · cartera, plantilla y seguimiento de firmas
--   ranking_red        · vista calculada a partir de los contratos firmados
-- =============================================================================

-- =============================================================================
-- 1 · AGENTES AUTÓNOMOS
-- El webhook es lo que conecta cada agente con su motor (n8n, Make, VAPI...).
-- Vive en la base de datos, no en el HTML, para que no se publique por error.
-- =============================================================================
do $$ begin
  create type public.tipo_agente as enum
    ('email','whatsapp','voice','content','marketing','ceo');
exception when duplicate_object then null; end $$;

do $$ begin
  create type public.estado_agente as enum ('active','paused','working','offline');
exception when duplicate_object then null; end $$;

create table if not exists public.agentes (
  id           text primary key,
  nombre       text not null,
  tipo         public.tipo_agente not null,
  estado       public.estado_agente not null default 'offline',
  descripcion  text not null default '',
  autonomia    text not null default 'Sugiere y espera aprobación'
               check (autonomia in ('Actúa solo','Sugiere y espera aprobación','Solo informa')),
  webhook      text check (webhook is null or webhook ~ '^https://'),
  metricas     jsonb not null default '{}'::jsonb,
  ultimo_latido timestamptz,
  creado       timestamptz not null default now(),
  actualizado  timestamptz not null default now()
);

comment on column public.agentes.autonomia is
  'Cuánto puede hacer sin permiso. «Actúa solo» significa que ejecuta cambios en el CRM sin que nadie lo apruebe: úsalo con cuidado.';

insert into public.agentes (id, nombre, tipo, descripcion, autonomia) values
  ('ag-mail','Agente de Correo','email',
   'Redacta, responde y clasifica el correo entrante de la red comercial.','Sugiere y espera aprobación'),
  ('ag-wsp','Agente de WhatsApp','whatsapp',
   'Atiende conversaciones, cualifica leads y agenda citas.','Actúa solo'),
  ('ag-voz','Agente de Voz','voice',
   'Atiende llamadas 24/7, recoge el motivo y avisa al responsable.','Actúa solo'),
  ('ag-cont','Agente de Contenido','content',
   'Prepara propuestas, publicaciones y material comercial.','Sugiere y espera aprobación'),
  ('ag-mkt','Agente de Marketing','marketing',
   'Lanza y vigila campañas, y reparte los leads que llegan.','Sugiere y espera aprobación'),
  ('ag-ceo','Agente Director','ceo',
   'Revisa el rendimiento de la red y propone prioridades del día.','Solo informa')
on conflict (id) do update
  set nombre = excluded.nombre, descripcion = excluded.descripcion;

-- Lo que cada agente ha hecho. Solo se escribe cuando ocurre de verdad: si la
-- tabla está vacía, el panel muestra «sin actividad» y no rellena el hueco.
create table if not exists public.agente_acciones (
  id           bigserial primary key,
  agente_id    text not null references public.agentes(id) on delete cascade,
  ts           timestamptz not null default now(),
  accion       text not null,
  detalle      text not null default '',
  resultado    text check (resultado in ('ok','error','pendiente')) default 'ok',
  expediente_id bigint references public.expedientes(id) on delete set null,
  aprobado_por uuid references public.perfiles(id) on delete set null
);
create index if not exists agente_acciones_idx on public.agente_acciones(agente_id, ts desc);

-- =============================================================================
-- 2 · CONTRATOS
-- =============================================================================
do $$ begin
  create type public.estado_contrato as enum ('Borrador','Enviado','Firmado','Anulado');
exception when duplicate_object then null; end $$;

create table if not exists public.contratos (
  id              bigserial primary key,
  codigo          text not null unique,
  -- cliente
  cliente         text not null,
  cif             text not null default '',
  domicilio       text not null default '',
  representante   text not null default '',
  email           text not null default '',
  telefono        text not null default '',
  -- servicio y condiciones
  servicio        text not null,
  setup           numeric(10,2) not null default 0,
  mensual         numeric(10,2) not null default 0,
  meses           int not null default 12 check (meses between 1 and 120),
  iva             numeric(5,2) not null default 21,
  inicio          date not null default current_date,
  observaciones   text not null default '',
  -- seguimiento
  estado          public.estado_contrato not null default 'Borrador',
  enviado_el      timestamptz,
  enviado_por     text check (enviado_por in ('whatsapp','email')),
  firmado_el      date,
  gestor_id       uuid references public.perfiles(id) on delete set null,
  expediente_id   bigint references public.expedientes(id) on delete set null,
  documento_ruta  text,                      -- PDF en el bucket «documentos»
  creado          timestamptz not null default now(),
  actualizado     timestamptz not null default now()
);
create index if not exists contratos_estado_idx on public.contratos(estado);
create index if not exists contratos_gestor_idx on public.contratos(gestor_id);

-- El DNI del representante NO se guarda aquí a propósito: es un dato personal
-- que solo hace falta en el momento de firmar. Si necesitáis conservarlo, va
-- en el bucket privado junto al contrato escaneado, nunca en una columna de
-- texto que aparece en cualquier consulta.

drop trigger if exists contratos_actualizado on public.contratos;
create trigger contratos_actualizado before update on public.contratos
  for each row execute function public.marca_actualizado();

drop trigger if exists agentes_actualizado on public.agentes;
create trigger agentes_actualizado before update on public.agentes
  for each row execute function public.marca_actualizado();

-- =============================================================================
-- 3 · RANKING DE LA RED
-- No es una tabla: se calcula de los contratos firmados, así nunca puede
-- discrepar de la realidad ni hay que mantenerlo a mano.
-- =============================================================================
create or replace view public.ranking_red as
select
  p.id                                              as distribuidor_id,
  trim(p.nombre || ' ' || p.apellidos)              as distribuidor,
  coalesce(sum(c.setup + c.mensual * c.meses), 0)   as volumen,
  count(c.id)                                       as cierres,
  round(coalesce(sum(c.setup + c.mensual * c.meses), 0) * 0.10, 2) as comision,
  rank() over (order by coalesce(sum(c.setup + c.mensual * c.meses), 0) desc) as posicion
from public.perfiles p
left join public.contratos c
  on c.gestor_id = p.id and c.estado = 'Firmado'
where p.estado = 'Activo' and p.rol in ('commercial','manager','admin')
group by p.id, p.nombre, p.apellidos;

comment on view public.ranking_red is
  'Ranking calculado de los contratos firmados. La comisión al 10 % es el valor por defecto: ajústalo si vuestro acuerdo con la red es otro.';

-- =============================================================================
-- 4 · RLS
-- =============================================================================
alter table public.agentes         enable row level security;
alter table public.agente_acciones enable row level security;
alter table public.contratos       enable row level security;

-- --- agentes: los ve dirección; solo administración los configura ---------
drop policy if exists agentes_lee     on public.agentes;
drop policy if exists agentes_admin   on public.agentes;
create policy agentes_lee on public.agentes
  for select using (public.mi_rol() in ('admin','manager'));
create policy agentes_admin on public.agentes
  for all using (public.soy_admin()) with check (public.soy_admin());

drop policy if exists acciones_lee   on public.agente_acciones;
drop policy if exists acciones_crea  on public.agente_acciones;
create policy acciones_lee on public.agente_acciones
  for select using (public.mi_rol() in ('admin','manager'));
create policy acciones_crea on public.agente_acciones
  for insert with check (auth.uid() is not null);
-- Sin UPDATE ni DELETE: lo que un agente hizo queda registrado.

-- --- contratos: cada comercial ve los suyos; dirección los ve todos -------
drop policy if exists contratos_lee    on public.contratos;
drop policy if exists contratos_crea   on public.contratos;
drop policy if exists contratos_edita  on public.contratos;
drop policy if exists contratos_borra  on public.contratos;

create policy contratos_lee on public.contratos
  for select using (
    public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid()
  );
create policy contratos_crea on public.contratos
  for insert with check (public.puedo('presu.crear') and gestor_id = auth.uid());
create policy contratos_edita on public.contratos
  for update using (
    public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid()
  ) with check (
    public.mi_rol() in ('admin','manager','backoffice') or gestor_id = auth.uid()
  );
create policy contratos_borra on public.contratos
  for delete using (public.puedo('exp.borrar'));

grant select, insert, update, delete on public.agentes, public.agente_acciones,
  public.contratos to authenticated;
grant select on public.ranking_red to authenticated;
grant usage, select on all sequences in schema public to authenticated;

-- =============================================================================
-- COMPROBACIÓN
-- =============================================================================
select
  (select count(*) from public.agentes)   as agentes,
  (select count(*) from public.contratos) as contratos,
  (select count(*) from public.ranking_red) as en_ranking,
  (select count(*) from pg_policies
   where schemaname = 'public'
     and tablename in ('agentes','agente_acciones','contratos')) as politicas;
