// =============================================================================
// LABS COMMAND CENTER 360™ · Edge Function «admin-usuarios»
//
// POR QUÉ EXISTE
//   Crear una cuenta, restablecer una contraseña o borrar un usuario exige la
//   clave de servicio de Supabase, que se salta todas las políticas RLS. Esa
//   clave NO puede vivir en el index.html: quien abra la web la vería. Aquí
//   está a salvo: la función se ejecuta en los servidores de Supabase y la
//   clave llega por variable de entorno.
//
//   El panel llama a esta función con el token de sesión del administrador.
//   Lo primero que hace la función es comprobar quién llama y si es admin.
//
//   Dos excepciones:
//   · quien tenga el permiso «sys.alta_agentes» puede usar el ALTA, solo
//     para cuentas de agente (Gestión Comercial);
//   · VER COMO: cualquiera puede entrar en la cuenta de quien tiene a su
//     cargo (perfiles.superior_id); el admin, en cualquiera de rango menor;
//     el Super Administrador de raíz, en cualquiera. Queda en la bitácora.
//   Contraseñas y borrados siguen siendo exclusivos del admin.
//
// DESPLIEGUE
//   supabase functions deploy admin-usuarios --project-ref ezwhkpfqnzyfulivlows
//   (SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY los inyecta Supabase solo)
//
// RUTAS
//   POST   /admin-usuarios              alta de usuario
//   POST   /admin-usuarios/:id/password restablecer contraseña
//   DELETE /admin-usuarios/:id          eliminar cuenta
//   POST   /admin-usuarios/:id/ver-como entrar en la cuenta de alguien a tu cargo
//   POST   /admin-usuarios/:id/correo   cambiar el correo (acceso y ficha a la vez)
// =============================================================================
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.45.4';

const URL_SB      = Deno.env.get('SUPABASE_URL')!;
const CLAVE_SERV  = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
const CLAVE_PUB   = Deno.env.get('SUPABASE_ANON_KEY')!;
// Dominio del panel. Sin esto, cualquier web podría llamar a la función desde
// el navegador de un administrador que tuviera la sesión abierta, así que no
// hay valor por defecto: si falta la variable de entorno, la función se
// niega a servir peticiones en vez de abrir CORS a "*" en una función que
// puede crear y borrar cuentas.
const ORIGEN = Deno.env.get('FRONTEND_ORIGIN');
if (!ORIGEN) {
  throw new Error('Falta la variable de entorno FRONTEND_ORIGIN: configúrala en el proyecto de Supabase antes de desplegar esta función.');
}

const ROLES    = ['admin', 'manager', 'commercial', 'backoffice'];
const CLAVE_MIN = 10;

const cabeceras = {
  'Access-Control-Allow-Origin': ORIGEN,
  'Access-Control-Allow-Headers': 'authorization, apikey, content-type',
  'Access-Control-Allow-Methods': 'POST, DELETE, OPTIONS',
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff'
};

function responde(cuerpo: unknown, estado = 200) {
  return new Response(JSON.stringify(cuerpo), { status: estado, headers: cabeceras });
}
function error(mensaje: string, code: string, estado = 400) {
  return responde({ error: mensaje, code }, estado);
}

// --- política corporativa de contraseñas, la misma que en el panel ----------
function revisaClave(p: string, datos: { email?: string; nombre?: string; apellidos?: string } = {}) {
  const f: string[] = [];
  if (typeof p !== 'string' || p.length < CLAVE_MIN) f.push(`al menos ${CLAVE_MIN} caracteres`);
  if (typeof p !== 'string') return f;
  if (p.length > 200)          f.push('un máximo de 200 caracteres');
  if (!/[A-ZÁÉÍÓÚÑ]/.test(p))  f.push('una mayúscula');
  if (!/[a-záéíóúñ]/.test(p))  f.push('una minúscula');
  if (!/[0-9]/.test(p))        f.push('un número');
  if (!/[^A-Za-z0-9]/.test(p)) f.push('un símbolo');
  if (/(.)\1{3,}/.test(p))     f.push('no repetir el mismo carácter cuatro veces');
  const partes = [datos.email?.split('@')[0], datos.nombre, datos.apellidos]
    .filter((x): x is string => !!x && x.length > 2).map(x => x.toLowerCase());
  if (partes.some(x => p.toLowerCase().includes(x))) f.push('no contener su nombre ni su correo');
  return f;
}

function claveAleatoria() {
  const may = 'ABCDEFGHJKLMNPQRSTUVWXYZ', min = 'abcdefghijkmnopqrstuvwxyz',
        num = '23456789', sig = '!@#$%&*';
  const az = (s: string) => s[crypto.getRandomValues(new Uint32Array(1))[0] % s.length];
  const base = [az(may), az(may), az(min), az(min), az(min), az(min),
                az(num), az(num), az(sig), az(sig), az(min), az(num)];
  for (let i = base.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1);
    [base[i], base[j]] = [base[j], base[i]];
  }
  return base.join('');
}

function nuevoRelacion() {
  const n = () => 100 + (crypto.getRandomValues(new Uint32Array(1))[0] % 900);
  return `0-${n()}-${n()}`;
}

// Alias del correo de raíz: todas estas grafías son la misma identidad.
const RAIZ_EMAIL = 'jalvarez@labs24k.com';
const RAIZ_ALIAS = ['jálvarez@labs24k.com', 'j.alvarez@labs24k.com',
                    'juan.alvarez@labs24k.com', 'admin@labs24k.com'];
const normalizaEmail = (e: string) => {
  const t = String(e || '').trim().toLowerCase();
  return RAIZ_ALIAS.includes(t) ? RAIZ_EMAIL : t;
};

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cabeceras });

  // --- quién llama --------------------------------------------------------
  const autorizacion = req.headers.get('Authorization') ?? '';
  if (!autorizacion.startsWith('Bearer ')) {
    return error('Sesión no iniciada.', 'SIN_SESION', 401);
  }

  // Cliente con la sesión del que llama: sirve para saber quién es, y sigue
  // sujeto a RLS, así que no puede usarse para saltarse nada.
  const comoUsuario = createClient(URL_SB, CLAVE_PUB, {
    global: { headers: { Authorization: autorizacion } }
  });
  const { data: sesion, error: eSesion } = await comoUsuario.auth.getUser();
  if (eSesion || !sesion?.user) return error('Sesión no válida.', 'SESION_INVALIDA', 401);

  const { data: quien } = await comoUsuario
    .from('perfiles')
    .select('id, nombre, apellidos, rol, estado, raiz, permisos')
    .eq('id', sesion.user.id)
    .single();

  const url    = new URL(req.url);
  const trozos = url.pathname.split('/').filter(Boolean);   // [ 'admin-usuarios', id?, 'password'? ]
  const id     = trozos[1];
  const accion = trozos[2];

  const activo   = !!quien && quien.estado === 'Activo';
  const esAdmin  = activo && quien.rol === 'admin';
  // Alta delegada: solo la ruta de alta. El Jefe de Equipo puede dar de alta
  // cuentas de rango inferior (Gestión Comercial y Back Office); quien tenga
  // el permiso «sys.alta_agentes», solo agentes. Los roles se fuerzan abajo.
  const ROLES_DELEGADOS = quien?.rol === 'manager' ? ['commercial', 'backoffice'] : ['commercial'];
  const altaDelegada = !esAdmin && activo && req.method === 'POST' && !id &&
                       (quien.rol === 'manager' || quien.permisos?.['sys.alta_agentes'] === true);

  // Ver como: la regla de quién puede entrar en qué cuenta se comprueba abajo,
  // con la ficha del destino delante.
  const verComo = activo && req.method === 'POST' && !!id && accion === 'ver-como';

  if (!esAdmin && !altaDelegada && !verComo) {
    console.warn('Acceso denegado a admin-usuarios', { usuario: sesion.user.id, rol: quien?.rol });
    return error('Esta operación es exclusiva del administrador.', 'ROL_INSUFICIENTE', 403);
  }

  // Cliente con la clave de servicio: solo a partir de aquí, y solo porque ya
  // sabemos que quien llama es administrador activo o tiene el alta delegada.
  const admin = createClient(URL_SB, CLAVE_SERV, { auth: { persistSession: false } });

  async function anota(destino: { id: string; nombre: string } | null, accionTxt: string, detalle = '') {
    await admin.from('bitacora').insert({
      actor_id: quien.id,
      actor_nombre: `${quien.nombre} ${quien.apellidos ?? ''}`.trim(),
      actor_rol: quien.rol,
      destino_id: destino?.id ?? null,
      destino_nombre: destino?.nombre ?? null,
      accion: accionTxt,
      detalle,
      ip: req.headers.get('x-forwarded-for'),
      agente: (req.headers.get('user-agent') ?? '').slice(0, 200)
    });
  }

  try {
    // =====================================================================
    // VER COMO · sesión en la cuenta de un agente
    // Se genera un enlace mágico para el agente y se canjea aquí mismo: no
    // se envía ningún correo y la contraseña del agente no se toca.
    // =====================================================================
    if (verComo) {
      const { data: destino } = await admin.from('perfiles')
        .select('id, nombre, apellidos, email, rol, estado, raiz, superior_id').eq('id', id).single();
      if (!destino) return error('Usuario no encontrado.', 'NO_ENCONTRADO', 404);
      if (destino.id === quien.id) return error('Ya estás en tu cuenta.', 'MISMA_CUENTA', 409);
      if (destino.raiz) {
        return error('En la cuenta del Super Administrador no se puede entrar.', 'RAIZ_PROTEGIDA', 403);
      }
      const aSuCargo = destino.superior_id === quien.id;
      const porRango = quien.raiz || (quien.rol === 'admin' && destino.rol !== 'admin');
      if (!aSuCargo && !porRango) {
        return error('Solo puedes entrar en las cuentas de las personas que tienes a tu cargo.',
                     'NO_ES_DE_TU_EQUIPO', 403);
      }
      if (destino.estado !== 'Activo') {
        return error('Esa cuenta no está activa.', 'CUENTA_INACTIVA', 409);
      }

      const { data: enlace, error: eEnlace } = await admin.auth.admin.generateLink({
        type: 'magiclink', email: destino.email
      });
      const hash = enlace?.properties?.hashed_token;
      if (eEnlace || !hash) {
        return error('No se ha podido abrir la cuenta: ' + (eEnlace?.message ?? ''), 'VER_COMO', 500);
      }
      const anonimo = createClient(URL_SB, CLAVE_PUB, {
        auth: { persistSession: false, autoRefreshToken: false }
      });
      const { data: canje, error: eCanje } = await anonimo.auth.verifyOtp({
        token_hash: hash, type: 'magiclink'
      });
      if (eCanje || !canje?.session) {
        return error('No se ha podido abrir la cuenta: ' + (eCanje?.message ?? ''), 'VER_COMO', 500);
      }

      const nombreDestino = `${destino.nombre} ${destino.apellidos ?? ''}`.trim();
      await anota({ id: destino.id, nombre: nombreDestino }, 'Entrada con «Ver como»',
                  `${quien.nombre} ${quien.apellidos ?? ''}`.trim() + ' ha entrado en su cuenta.');

      const s = canje.session;
      return responde({
        sesion: { access_token: s.access_token, refresh_token: s.refresh_token,
                  expires_in: s.expires_in, user: { id: s.user.id } },
        agente: { id: destino.id, nombre: nombreDestino, email: destino.email }
      });
    }

    // =====================================================================
    // ALTA DE USUARIO
    // =====================================================================
    if (req.method === 'POST' && !id) {
      const b = await req.json().catch(() => ({}));
      const nombre    = String(b.nombre ?? '').trim();
      const apellidos = String(b.apellidos ?? '').trim();
      const email     = normalizaEmail(b.email ?? '');

      if (nombre.length < 2)  return error('Nombre no válido.', 'NOMBRE_INVALIDO');
      if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(email)) return error('Correo no válido.', 'EMAIL_INVALIDO');
      if (!ROLES.includes(b.rol)) return error('Rol no válido.', 'ROL_INVALIDO');
      if (altaDelegada && !ROLES_DELEGADOS.includes(b.rol)) {
        return error(quien.rol === 'manager'
          ? 'Solo puedes dar de alta cuentas de Gestión Comercial o Back Office.'
          : 'Solo puedes dar de alta agentes (Gestión Comercial).', 'ROL_NO_PERMITIDO', 403);
      }
      if (b.prefijo && !/^\+\d{1,3}$/.test(String(b.prefijo))) {
        return error('El prefijo debe ser internacional, como +34.', 'PREFIJO_INVALIDO');
      }

      // Superior: en un alta delegada, quien la hace; si la hace un admin, el
      // que elija o, si no elige, él mismo. La base de datos comprueba que el
      // superior tenga más rango (14-superiores.sql).
      let superiorId: string | null = quien.id;
      if (esAdmin && b.superior_id) {
        const { data: sup } = await admin.from('perfiles')
          .select('id, estado').eq('id', String(b.superior_id)).maybeSingle();
        if (!sup || sup.estado !== 'Activo') return error('El superior elegido no es válido.', 'SUPERIOR_INVALIDO');
        superiorId = sup.id;
      }
      // El superior tiene que tener más rango; si no (un admin que da de alta
      // a otro admin), la nueva cuenta cuelga del Super Administrador.
      const rango = (rol: string, raiz: boolean) =>
        raiz ? 4 : rol === 'admin' ? 3 : rol === 'manager' ? 2 : 1;
      const { data: supFila } = await admin.from('perfiles')
        .select('rol, raiz').eq('id', superiorId).maybeSingle();
      if (!supFila || rango(supFila.rol, supFila.raiz) <= rango(b.rol, false)) {
        const { data: raiz } = await admin.from('perfiles').select('id').eq('raiz', true).maybeSingle();
        superiorId = raiz?.id ?? null;
      }

      const { data: yaExiste } = await admin.from('perfiles').select('id').eq('email', email).maybeSingle();
      if (yaExiste) return error('Ya existe una cuenta con ese correo.', 'EMAIL_DUPLICADO', 409);

      let password = String(b.password ?? '') || claveAleatoria();
      const faltan = revisaClave(password, { email, nombre, apellidos });
      if (faltan.length) {
        return error('La contraseña necesita ' + faltan.join(', ') + '.', 'CLAVE_DEBIL');
      }

      // 1 · identidad en Supabase Auth
      const { data: creado, error: eAuth } = await admin.auth.admin.createUser({
        email, password, email_confirm: true,
        user_metadata: { nombre, apellidos }
      });
      if (eAuth || !creado?.user) {
        return error('No se ha podido crear la identidad: ' + (eAuth?.message ?? ''), 'ALTA_AUTH', 500);
      }

      // 2 · ficha en perfiles
      const { data: permisos } = await admin.rpc('permisos_de_rol', { p_rol: b.rol });
      const { data: perfil, error: ePerfil } = await admin.from('perfiles').insert({
        id: creado.user.id,
        nombre, apellidos, email,
        prefijo: b.prefijo ?? '+34',
        telefono: String(b.telefono ?? '').trim(),
        extension: String(b.extension ?? ''),
        rol: b.rol,
        rel: nuevoRelacion(),
        google: b.google === true,
        estado: 'Activo',
        debe_cambiar: true,
        superior_id: superiorId,
        permisos,
        api_token: 'lk_' + crypto.randomUUID().replace(/-/g, '')
      }).select().single();

      if (ePerfil) {
        // Si la ficha falla, no dejamos una identidad huérfana en Auth.
        await admin.auth.admin.deleteUser(creado.user.id);
        return error('No se ha podido crear la ficha: ' + ePerfil.message, 'ALTA_PERFIL', 500);
      }

      if (altaDelegada) {
        await anota({ id: perfil.id, nombre: `${nombre} ${apellidos}`.trim() },
                    'Cuenta creada', `Alta delegada (${b.rol}) · relación ${perfil.rel}`);
      }

      // La contraseña en claro sale UNA vez, para entregarla en mano.
      return responde({ usuario: perfil, passwordInicial: password }, 201);
    }

    // =====================================================================
    // CAMBIAR EL CORREO · en la identidad de Auth y en la ficha a la vez
    // Si solo se cambiara en perfiles, la persona seguiría entrando con el
    // correo antiguo y su ficha diría otro: por eso va por aquí.
    // =====================================================================
    if (req.method === 'POST' && id && accion === 'correo') {
      const b = await req.json().catch(() => ({}));
      const nuevo = normalizaEmail(b.email ?? '');
      if (!/^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i.test(nuevo)) return error('Correo no válido.', 'EMAIL_INVALIDO');

      const { data: destino } = await admin.from('perfiles')
        .select('id, nombre, apellidos, email, raiz').eq('id', id).single();
      if (!destino) return error('Usuario no encontrado.', 'NO_ENCONTRADO', 404);
      if (destino.raiz) return error('El correo de la cuenta de raíz no se cambia.', 'RAIZ_EMAIL_FIJO', 409);
      if (destino.email === nuevo) return responde({ ok: true, email: nuevo });

      const { data: yaExiste } = await admin.from('perfiles').select('id').eq('email', nuevo).maybeSingle();
      if (yaExiste) return error('Ya existe una cuenta con ese correo.', 'EMAIL_DUPLICADO', 409);

      const { error: eAuth } = await admin.auth.admin.updateUserById(id, { email: nuevo, email_confirm: true });
      if (eAuth) return error('No se ha podido cambiar el correo: ' + eAuth.message, 'CORREO_AUTH', 500);
      const { error: eFicha } = await admin.from('perfiles').update({ email: nuevo }).eq('id', id);
      if (eFicha) {
        await admin.auth.admin.updateUserById(id, { email: destino.email, email_confirm: true });
        return error('No se ha podido cambiar el correo: ' + eFicha.message, 'CORREO_FICHA', 500);
      }
      await anota({ id, nombre: `${destino.nombre} ${destino.apellidos ?? ''}`.trim() },
                  'Correo cambiado', `${destino.email} → ${nuevo}`);
      return responde({ ok: true, email: nuevo });
    }

    // =====================================================================
    // RESTABLECER CONTRASEÑA
    // =====================================================================
    if (req.method === 'POST' && id && accion === 'password') {
      const b = await req.json().catch(() => ({}));
      const { data: destino } = await admin.from('perfiles')
        .select('id, nombre, apellidos, email').eq('id', id).single();
      if (!destino) return error('Usuario no encontrado.', 'NO_ENCONTRADO', 404);

      const password = String(b.password ?? '') || claveAleatoria();
      const faltan = revisaClave(password, destino);
      if (faltan.length) {
        return error('La contraseña necesita ' + faltan.join(', ') + '.', 'CLAVE_DEBIL');
      }

      const { error: e } = await admin.auth.admin.updateUserById(id, { password });
      if (e) return error('No se ha podido restablecer: ' + e.message, 'RESET', 500);

      await admin.from('perfiles').update({ debe_cambiar: true }).eq('id', id);
      await admin.from('sesiones').delete().eq('usuario_id', id);
      await anota({ id, nombre: `${destino.nombre} ${destino.apellidos ?? ''}`.trim() },
                  'Contraseña restablecida',
                  'Deberá cambiarla en el próximo acceso. Sesiones cerradas.');

      return responde({ ok: true, passwordInicial: password });
    }

    // =====================================================================
    // ELIMINAR CUENTA
    // =====================================================================
    if (req.method === 'DELETE' && id) {
      const { data: destino } = await admin.from('perfiles')
        .select('id, nombre, apellidos, rel, rol, raiz').eq('id', id).single();
      if (!destino) return error('Usuario no encontrado.', 'NO_ENCONTRADO', 404);

      if (destino.raiz) {
        await anota({ id, nombre: destino.nombre }, 'Intento bloqueado sobre la cuenta de raíz',
                    'Se intentó eliminar el Super Administrador de raíz.');
        return error('El Super Administrador de raíz no se puede eliminar.', 'RAIZ_INDESTRUCTIBLE', 409);
      }
      if (destino.id === quien.id) {
        return error('No puedes eliminar tu propia cuenta.', 'AUTO_BORRADO', 409);
      }

      await anota({ id, nombre: `${destino.nombre} ${destino.apellidos ?? ''}`.trim() },
                  'Cuenta eliminada', `relación ${destino.rel} · ${destino.rol}`);

      // Borrar la identidad arrastra la ficha por la clave foránea en cascada.
      const { error: e } = await admin.auth.admin.deleteUser(id);
      if (e) return error('No se ha podido eliminar: ' + e.message, 'BORRADO', 500);

      return responde({ ok: true });
    }

    return error('Operación no reconocida.', 'RUTA_DESCONOCIDA', 404);

  } catch (e) {
    console.error('Fallo en admin-usuarios', e);
    return error('Error interno.', 'EXCEPCION', 500);
  }
});
