# Labs Command Center 360™ — Instalación en Hostalia

Oficina virtual de la red comercial de **Labs24k** (Grupo Evolvix Global, S.L.).

Dos páginas HTML autocontenidas, sin Node, sin npm, sin build y sin CDN. Se suben
por FTP y funcionan. Los datos viven en **Supabase**; el navegador habla con él
directamente por `fetch`.

---

## 1. Qué llevas en el paquete

| Archivo | Qué es | ¿Se sube? |
|---|---|---|
| `index.html` | El panel completo (HTML + CSS + JS + iconos SVG) | **Sí** |
| `firmar.html` | La página que abre el **cliente** para firmar su contrato | **Sí** |
| `.htaccess` | Cabeceras de seguridad, CSP y compresión | **Sí** (ver aviso) |
| `htaccess-blindado.txt` | Versión más estricta, para instalar después | Sólo si el otro va bien |
| `test.html` | Diagnóstico: comprueba que el hosting sirve HTML y JS | Opcional |
| `supabase/*.sql` | Los guiones de la base de datos | **No** (se pegan en Supabase) |
| `backend/` | La Edge Function de administración de usuarios | **No** (se despliega aparte) |
| `LEEME-*.md`, `ejemplo-*.pdf` | Documentación y muestras | No |

`index.html` pesa unos **570 KB** y `firmar.html` unos **105 KB**. Cargan de una vez
y luego no piden nada más al servidor.

> **Aviso sobre el `.htaccess`.** Ahora mismo lo tienes desactivado en el servidor.
> Mientras siga así, el sitio funciona pero **sin CSP ni cabeceras de seguridad**.
> Vuelve a ponerlo en cuanto puedas: el del paquete es el «compatible», pensado
> para que Hostalia no dé error 500.

---

## 2. Subida por FTP

1. Panel de Hostalia → **Alojamiento → Accesos FTP**: copia servidor, usuario y contraseña.
2. Conecta con FileZilla o con el Administrador de archivos del panel.
3. Entra en la carpeta pública del dominio (en Hostalia suele ser `/httpdocs` o `/public_html`).
4. Sube **`index.html`, `firmar.html` y `.htaccess`** en la misma carpeta.

Los dos HTML tienen que estar **juntos**: el enlace de firma que genera el panel
apunta a `firmar.html` en su misma ruta.

> El `.htaccess` lleva el hash SHA-256 de los dos ficheros. Si vuelves a generar el
> paquete, sube los tres a la vez o el navegador bloqueará la página que no cuadre.

---

## 3. La base de datos (Supabase)

Proyecto: `ezwhkpfqnzyfulivlows`. En el editor SQL, **en este orden**:

| Guion | Qué crea |
|---|---|
| `01-esquema.sql` | Perfiles, permisos, bitácora, sesiones, expedientes, y el blindaje de la cuenta raíz |
| `02-cuenta-raiz.sql` | La cuenta `jalvarez@labs24k.com` con su contraseña inicial |
| `03-almacen.sql` | El depósito privado `documentos` |
| `04-mission-contratos.sql` | Agentes, contratos y el ranking de la red |
| `05-firma-contratos.sql` | La firma del contrato por el cliente |
| `06-endurecimiento.sql` | Cierra huecos de seguridad encontrados en auditoría (obligatorio) |
| `07-contactos.sql` | Módulo de Contactos: fichas de leads y clientes |
| `08-roles-personalizados.sql` | Plantillas de rol y permisos, y control de qué pestañas ve cada usuario |
| `09-recursos.sql` | Centro de Descarga de Dosieres: repositorio documental por categorías, con analítica de descargas |
| `10-soporte.sql` | Soporte y Tickets: escalado a dos niveles (Responsable de Soporte / Responsable del Responsable) con asignación automática por reglas |
| `11-soporte-global.sql` | Mesa de Incidencias: vista de solo lectura con cálculo de SLA por prioridad, para el panel centralizado de admin/manager |

Después:

- **Authentication → URL Configuration**: añade `https://crm.labs24k.com` a las URL permitidas.
- Despliega la Edge Function `admin-usuarios` (carpeta `backend/`). Es la única
  que usa la clave de servicio.

### Las claves

- La **publicable** (`sb_publishable_…`) va dentro del HTML a propósito. Por sí sola
  no da acceso a nada: quien decide qué se puede leer o escribir son las políticas
  RLS de la base de datos.
- La **de servicio** (`sb_secret_…`) se salta todas las políticas. **Nunca** va en el
  panel, ni en un correo, ni en un chat. Vive sólo en la Edge Function.

---

## 4. Entrar

`https://crm.labs24k.com` → correo y contraseña.

**No hay acceso de demostración.** El botón «Entrar como admin» y las contraseñas de
ejemplo se eliminaron: sin credenciales reales contra Supabase no se entra.

Cuenta de raíz: **`jalvarez@labs24k.com`**. No se puede borrar, ni bloquear, ni
cambiarle el correo desde el panel — lo impiden disparadores de la propia base de
datos, no una comprobación del navegador. **Cambia su contraseña la primera vez que entres.**

---

## 5. Contratos y firma del cliente

El módulo **Contratos y Facturación** genera vuestro contrato real —el de prestación
de servicios de embudos y captación 24/7, con sus dieciséis cláusulas y su Anexo I—
rellenando solos los huecos entre corchetes del original.

Cómo funciona el envío a firma:

1. Rellenas el formulario y pulsas **Registrar contrato**. Se guarda en Supabase.
2. En la cartera, el botón del **enlace** pide a la base de datos un token de un solo
   uso y te devuelve una dirección `…/firmar.html#t=…`.
3. Se la mandas al cliente por WhatsApp o correo desde el propio panel.
4. El cliente abre el enlace: ve el contrato entero, escribe su nombre y DNI, firma
   con el dedo y le sale su copia en PDF.
5. En vuestro panel el contrato pasa a **Firmado**, con la fecha, la hora, la IP, el
   navegador y una huella SHA-256 del texto exacto que aceptó.

El enlace **caduca a los 30 días** y **sólo sirve una vez**.

### Qué validez tiene esa firma — léelo

Es una **firma electrónica simple** (art. 3.10 del Reglamento eIDAS). Es válida y
admisible como prueba, y las evidencias que se guardan (fecha, hora, IP, navegador,
huella del documento) son precisamente lo que la sostiene.

Pero conviene que sepas la diferencia: si el cliente niega haber firmado, **la carga
de demostrar que fue él es vuestra**. Con una firma cualificada de un prestador
acreditado (Signaturit, Firmafy, Uanataca y similares) la carga se invierte.

Recomendación honesta: usa esta firma para el día a día y para contratos de importe
normal; para los grandes, pasa por un prestador cualificado. Y en cualquier caso,
que vuestro asesor legal revise el circuito antes de usarlo con clientes.

---

## 6. Lo que aún no está conectado

Estas partes están construidas pero **esperando a que las enchufes**, y el panel lo
dice claramente en vez de fingir que funcionan:

- **Mission Control.** Los seis agentes salen como «Sin conectar» hasta que les des
  una URL de webhook `https://` (n8n, Make, VAPI…). No se inventa actividad: si no
  ha pasado nada, no aparece nada.
- **Control por voz.** Funciona en Chrome y Edge. Ojo: el navegador manda el audio a
  los servidores de Google para transcribirlo. El panel lo advierte antes de escuchar.
- **Integraciones**: IMAP/SMTP del webmail de Hostalia, la API de app.metatok.ai y
  VAPI/Twilio.

---

## 7. Lo que se ha comprobado de verdad

- **158 comprobaciones automáticas** con navegador real (Playwright), en cinco
  baterías: acceso cerrado, usuarios y permisos, integración con Supabase, informes
  y descargas, y ranking / Mission Control / voz / contratos.
- **Circuito completo de firma probado de punta a punta**: emitir el enlace, abrirlo
  como cliente, dibujar la firma, enviarla, y comprobar que el enlace ya no sirve.
- **30 comprobaciones de la base de datos** contra un PostgreSQL real: quién puede
  emitir un enlace, qué ve el cliente con su token (y qué **no**), el rechazo de
  firmas falsas, la caducidad, y que `anon` no tiene acceso a ninguna tabla.
- **115 comprobaciones de seguridad del backend**, todas correctas.
- Sin errores de JavaScript en consola y **sin violaciones de CSP** en ninguna vista.
- Sin desplazamiento horizontal en móvil (probado a 390 px), panel y página de firma.
- Contraseñas con Argon2id, y bcrypt de coste 13 como respaldo. Nunca en texto plano.

---

## 8. Si algo falla

| Síntoma | Qué mirar |
|---|---|
| Página en blanco | Sube `test.html` y ábrelo. Si carga, el problema está en el `.htaccess` |
| Error 500 al entrar | El `.htaccess` no le gusta a tu Apache: renómbralo a `htaccess.txt` |
| «Sin conexión con Supabase» | Ajustes → Conexión: revisa la URL y que el dominio esté autorizado |
| Los botones de firma no hacen nada | Falta ejecutar `05-firma-contratos.sql` |
| El cliente ve «enlace no válido» | El token ya se usó o caducó: emite uno nuevo |

---

*Labs24k · Labs Command Center 360™ · Grupo Evolvix Global, S.L. · CIF B21779673*
