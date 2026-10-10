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
// DESPLIEGUE
//   supabase functions deploy admin-usuarios --project-ref ezwhkpfqnzyfulivlows
//   (SUPABASE_URL y SUPABASE_SERVICE_ROLE_KEY los inyecta Supabase solo)
//
// RUTAS
//   POST   /admin-usuarios              alta de usuario
//   POST   /admin-usuarios/:id/password restablecer contraseña
//   DELETE /admin-usuarios/:id          eliminar cuenta
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
    .select('id, nombre, apellidos, rol, estado, raiz')
    .eq('id', sesion.user.id)
    .single();

  if (!quien || quien.rol !== 'admin' || quien.estado !== 'Activo') {
    console.warn('Acceso denegado a admin-usuarios', { usuario: sesion.user.id, rol: quien?.rol });
    return error('Esta operación es exclusiva del administrador.', 'ROL_INSUFICIENTE', 403);
  }

  // Cliente con la clave de servicio: solo a partir de aquí, y solo porque ya
  // sabemos que quien llama es administrador activo.
  const admin = createClient(URL_SB, CLAVE_SERV, { auth: { persistSession: false } });

  const url    = new URL(req.url);
  const trozos = url.pathname.split('/').filter(Boolean);   // [ 'admin-usuarios', id?, 'password'? ]
  const id     = trozos[1];
  const accion = trozos[2];

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
      if (b.prefijo && !/^\+\d{1,3}$/.test(String(b.prefijo))) {
        return error('El prefijo debe ser internacional, como +34.', 'PREFIJO_INVALIDO');
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
        permisos,
        api_token: 'lk_' + crypto.randomUUID().replace(/-/g, '')
      }).select().single();

      if (ePerfil) {
        // Si la ficha falla, no dejamos una identidad huérfana en Auth.
        await admin.auth.admin.deleteUser(creado.user.id);
        return error('No se ha podido crear la ficha: ' + ePerfil.message, 'ALTA_PERFIL', 500);
      }

      // La contraseña en claro sale UNA vez, para entregarla en mano.
      return responde({ usuario: perfil, passwordInicial: password }, 201);
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
