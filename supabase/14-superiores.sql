-- =============================================================================
-- LABS COMMAND CENTER 360™ · Superiores (jerarquía) y «Ver como»
-- Ejecutar DESPUÉS de 13-fichas-agente.sql. Se puede volver a ejecutar.
--
-- Cada usuario tiene un superior (perfiles.superior_id), salvo el Super
-- Administrador de raíz, que está en lo más alto. El superior siempre es de
-- un rango mayor que la persona:
--
--     Super Administrador (raíz)  >  Administrador  >  Jefe de Equipo
--                                 >  Gestión Comercial / Back Office
--
-- Para qué sirve:
--   · Fichas de agente: el Jefe de Equipo ve y gestiona solo las de SUS
--     agentes. El Administrador, todas.
--   · «Ver como» (Edge Function admin-usuarios): se puede entrar en la cuenta
--     de quien tienes a tu cargo; el Administrador, en cualquiera de rango
--     inferior; el Super Administrador, en cualquiera.
-- El superior solo lo asigna un Administrador. Nadie se lo cambia a sí mismo.
-- =============================================================================

do $$
begin
  if to_regclass('public.agente_fichas') is null then
    raise exception 'Ejecuta antes 13-fichas-agente.sql.';
  end if;
end $$;

-- -----------------------------------------------------------------------------
-- 1 · COLUMNA
-- -----------------------------------------------------------------------------
alter table public.perfiles
  add column if not exists superior_id uuid references public.perfiles(id) on delete set null;
create index if not exists perfiles_superior_idx on public.perfiles(superior_id);
comment on column public.perfiles.superior_id is
  'Superior directo. Siempre de rango mayor. La raíz no tiene superior.';

-- -----------------------------------------------------------------------------
-- 2 · RANGO Y VALIDACIÓN
-- -----------------------------------------------------------------------------
create or replace function public.rango(p_rol public.rol_usuario, p_raiz boolean)
returns int language sql immutable as $$
  select case when p_raiz then 4
              when p_rol = 'admin' then 3
              when p_rol = 'manager' then 2
              else 1 end;
$$;

create or replace function public.valida_superior()
returns trigger language plpgsql security definer set search_path = public as $$
declare
  v_sup public.perfiles%rowtype;
begin
  if new.raiz then
    new.superior_id := null;          -- la raíz no tiene superior
    return new;
  end if;
  if new.superior_id is null then return new; end if;

  if new.superior_id = new.id then
    raise exception 'Nadie puede ser su propio superior.'
      using errcode = 'check_violation', hint = 'SUPERIOR_PROPIO';
  end if;

  select * into v_sup from public.perfiles where id = new.superior_id;
  if not found or public.rango(v_sup.rol, v_sup.raiz) <= public.rango(new.rol, new.raiz) then
    -- Si solo ha cambiado el rol (un ascenso, por ejemplo) y el superior de
    -- antes ya no encaja, se le quita el superior en vez de rechazar el cambio.
    if tg_op = 'UPDATE' and new.superior_id is not distinct from old.superior_id then
      new.superior_id := null;
      return new;
    end if;
    raise exception 'El superior tiene que tener un rango mayor que la persona.'
      using errcode = 'check_violation', hint = 'SUPERIOR_RANGO';
  end if;
  return new;
end $$;

drop trigger if exists perfiles_valida_superior on public.perfiles;
create trigger perfiles_valida_superior
  before insert or update of superior_id, rol, raiz on public.perfiles
  for each row execute function public.valida_superior();

-- Nadie se cambia a sí mismo el superior (mismo blindaje que rol y permisos).
create or replace function public.impide_autoescalada()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is not null and auth.uid() = new.id then
    if new.rol is distinct from old.rol
       or new.estado is distinct from old.estado
       or new.permisos is distinct from old.permisos
       or new.debe_cambiar is distinct from old.debe_cambiar
       or new.doble_factor is distinct from old.doble_factor
       or new.modulos_visibles is distinct from old.modulos_visibles
       or new.rol_personalizado_id is distinct from old.rol_personalizado_id
       or new.superior_id is distinct from old.superior_id then
      raise exception 'No puedes cambiar tu propio rol, estado, permisos, superior, doble factor, la marca de cambio de contraseña ni tus módulos visibles.'
        using errcode = 'insufficient_privilege', hint = 'AUTO_ESCALADA';
    end if;
  end if;
  return new;
end $$;

-- -----------------------------------------------------------------------------
-- 3 · QUIÉN DIRIGE A CADA AGENTE (sustituye a la regla básica del 13)
-- -----------------------------------------------------------------------------
create or replace function public.dirijo_agente(p_agente uuid)
returns boolean language sql stable security definer set search_path = public as $$
  select coalesce(public.mi_rol() = 'admin', false)
      or (public.mi_rol() is not null and exists (
            select 1 from public.perfiles where id = p_agente and superior_id = auth.uid()));
$$;
revoke execute on function public.dirijo_agente(uuid) from public;
grant  execute on function public.dirijo_agente(uuid) to authenticated;

-- Las políticas se vuelven a crear aquí por si el 13 se ejecutó en su primera
-- versión, que usaba otra función.
drop policy if exists agfichas_lee   on public.agente_fichas;
drop policy if exists agfichas_crea  on public.agente_fichas;
drop policy if exists agfichas_edita on public.agente_fichas;
create policy agfichas_lee on public.agente_fichas
  for select using (public.dirijo_agente(agente_id) or agente_id = auth.uid());
create policy agfichas_crea on public.agente_fichas
  for insert with check (public.dirijo_agente(agente_id));
create policy agfichas_edita on public.agente_fichas
  for update using (public.dirijo_agente(agente_id)) with check (public.dirijo_agente(agente_id));

drop policy if exists agseg_lee   on public.agente_seguimiento;
drop policy if exists agseg_crea  on public.agente_seguimiento;
drop policy if exists agseg_edita on public.agente_seguimiento;
drop policy if exists agseg_borra on public.agente_seguimiento;
create policy agseg_lee on public.agente_seguimiento
  for select using (public.dirijo_agente(agente_id) or agente_id = auth.uid());
create policy agseg_crea on public.agente_seguimiento
  for insert with check (
    public.dirijo_agente(agente_id) or (agente_id = auth.uid() and tipo = 'nota'));
create policy agseg_edita on public.agente_seguimiento
  for update using (public.dirijo_agente(agente_id) or agente_id = auth.uid())
  with check (public.dirijo_agente(agente_id) or agente_id = auth.uid());
create policy agseg_borra on public.agente_seguimiento
  for delete using (public.dirijo_agente(agente_id) or (agente_id = auth.uid() and autor_id = auth.uid()));

create or replace function public.agente_seguimiento_guarda()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'INSERT' then
    if not public.es_agente(new.agente_id) then
      raise exception 'Solo los agentes (Gestión Comercial) tienen ficha de agente.'
        using errcode = 'check_violation', hint = 'NO_ES_AGENTE';
    end if;
    if auth.uid() is not null then
      new.autor_id := auth.uid();
      select trim(nombre || ' ' || apellidos) into new.autor_nombre
        from public.perfiles where id = auth.uid();
    end if;
    new.creado := now();
    return new;
  end if;

  if auth.uid() is not null and not public.dirijo_agente(old.agente_id) then
    if new.agente_id    is distinct from old.agente_id
       or new.autor_id     is distinct from old.autor_id
       or new.autor_nombre is distinct from old.autor_nombre
       or new.tipo         is distinct from old.tipo
       or new.titulo       is distinct from old.titulo
       or new.texto        is distinct from old.texto
       or new.fecha        is distinct from old.fecha
       or new.creado       is distinct from old.creado then
      raise exception 'Solo puedes marcar como hecha una tarea de tu ficha.'
        using errcode = 'insufficient_privilege', hint = 'SOLO_HECHO';
    end if;
  end if;
  new.agente_id := old.agente_id;
  new.autor_id  := old.autor_id;
  new.creado    := old.creado;
  return new;
end $$;

-- -----------------------------------------------------------------------------
-- 4 · MARÍA PASA A ADMINISTRADORA, CON JUAN (RAÍZ) COMO SUPERIOR
-- Si su correo no es este, cámbialo aquí; si no coincide, no hace nada.
-- -----------------------------------------------------------------------------
update public.perfiles
set rol = 'admin', permisos = public.permisos_de_rol('admin')
where lower(email) = 'maria.alvarez@labs24k.com' and not raiz;

-- -----------------------------------------------------------------------------
-- 5 · QUIEN NO TENGA SUPERIOR, CUELGA DE LA RAÍZ
-- Punto de partida: después se reparten desde Usuarios y Accesos (por
-- ejemplo, los agentes de María, con María como superior).
-- -----------------------------------------------------------------------------
update public.perfiles p
set superior_id = r.id
from public.perfiles r
where r.raiz and not p.raiz and p.superior_id is null;

-- -----------------------------------------------------------------------------
-- COMPROBACIÓN
-- -----------------------------------------------------------------------------
select p.nombre || ' ' || p.apellidos as usuario,
       p.email,
       case when p.raiz then 'Super Administrador' else p.rol::text end as rol,
       coalesce(s.nombre || ' ' || s.apellidos, '— (es la raíz)') as superior
from public.perfiles p
left join public.perfiles s on s.id = p.superior_id
order by public.rango(p.rol, p.raiz) desc, p.nombre;
-- Esperado: Juan como Super Administrador sin superior, María como admin con
-- Juan de superior, y el resto colgando de Juan hasta que los repartas.
