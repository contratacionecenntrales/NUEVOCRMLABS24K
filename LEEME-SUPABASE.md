# Conectar el Command Center con Supabase

**Proyecto:** `ezwhkpfqnzyfulivlows`
**URL de la API:** `https://ezwhkpfqnzyfulivlows.supabase.co`

## Si solo quieres poder entrar: haz esto

Panel de Supabase → **SQL Editor** → *New query*. Abre cada archivo con el Bloc
de notas, copia **todo** el contenido, pégalo y pulsa **Run**. En este orden:

| Orden | Archivo | Para qué |
|---|---|---|
| 1 | `01-esquema.sql` | Tablas, permisos, bitácora y el blindaje de la cuenta raíz |
| 2 | `02-cuenta-raiz.sql` | **Crea tu usuario.** Sin esto no se puede entrar |
| 3 | `03-almacen.sql` | El depósito privado de documentos |
| 4 | `04-mission-contratos.sql` | Agentes, contratos y ranking de la red |
| 5 | `05-firma-contratos.sql` | La firma del contrato por el cliente |
| 6 | `06-endurecimiento.sql` | Cierra huecos de RLS de una auditoría de seguridad. **Obligatorio** |
| 7 | `07-contactos.sql` | Módulo de Contactos: ficha de leads y clientes con documentos, notas y comentarios |
| 8 | `08-roles-personalizados.sql` | Plantillas de rol reutilizables (permisos + pestañas visibles) aplicables a cualquier usuario |
| 9 | `09-recursos.sql` | Centro de Descarga de Dosieres: repositorio documental por categorías, con analítica de descargas |
| 10 | `10-soporte.sql` | Soporte y Tickets: escalado a dos niveles (Responsable de Soporte / Responsable del Responsable) con asignación automática por reglas |
| 11 | `11-soporte-global.sql` | Mesa de Incidencias: vista de solo lectura con cálculo de SLA por prioridad, para el panel centralizado de admin/manager |

Con el **1** y el **2** ya entras. El **6** es de seguridad y no es opcional.
Los demás son para los módulos correspondientes.

Si el 01 da error, **párate ahí**: los demás dependen de las tablas que crea, y
seguir solo acumula errores encima del primero.

> Los archivos `_stub-auth.sql`, `test-esquema.sql` y `test-firma.sql` **no se
> ejecutan en Supabase**. Son las pruebas que corren contra un PostgreSQL local.

---

## Antes de empezar: qué hace cada clave

| Clave | Empieza por | Dónde vive | Qué puede |
|---|---|---|---|
| **Publicable** | `sb_publishable_` | Dentro del `index.html`, a la vista | Nada por sí sola. Toda consulta se filtra por las políticas RLS según el rol de quien ha iniciado sesión |
| **Secreta** | `sb_secret_` | Solo en la Edge Function, dentro de Supabase | **Todo**: se salta las políticas |

La que me pasaste es la publicable, y está bien que sea pública: para eso
existe. **La secreta no me la envíes ni la pegues nunca en el panel.** Si acaba
en el HTML, cualquiera que abra la web tiene control total de la base de datos.
La encontrarás en *Project Settings → API keys* cuando la necesites para el
paso 3, y no sale de ahí.

---

## Paso 1 · Crear las tablas

1. Panel de Supabase → **SQL Editor** → *New query*
2. Pega entero el archivo **`01-esquema.sql`** y pulsa **Run**

Crea las tablas (`perfiles`, `bitacora`, `accesos_raiz`, `sesiones`,
`expedientes`, `candidatos`, `presupuestos`), el catálogo de los 18 permisos y
las políticas RLS. Se puede volver a ejecutar sin romper nada.

Lo que queda protegido por la propia base de datos, no por la aplicación:

- La cuenta de raíz no se elimina, no se suspende y no se le cambia el correo
  ni el rol. Da igual desde dónde llegue la orden.
- Nadie puede cambiarse a sí mismo el rol, el estado ni los permisos.
- El sistema nunca se queda sin ningún administrador activo.
- La bitácora se escribe sola en cada cambio y **no tiene política de UPDATE ni
  de DELETE**: desde la aplicación no se puede reescribir el pasado.

## Paso 2 · Crear tu cuenta

En el mismo editor, pega y ejecuta **`02-cuenta-raiz.sql`**.

Crea la identidad de Juan Álvarez en *Authentication* y su ficha en `perfiles`,
con el distintivo de raíz y los 18 permisos. Al final te devuelve una tabla de
comprobación.

```
correo       jalvarez@labs24k.com
contraseña   la que hayas puesto en v_clave dentro de 02-cuenta-raiz.sql
relación     0-413-936
```

También entras escribiendo `JÁlvarez@labs24k.com`: el panel resuelve las dos
grafías a la misma cuenta. La identidad se guarda sin tilde porque una tilde
antes de la arroba obliga al servidor de correo a hablar SMTPUTF8, y muchos
proveedores —Hostalia entre ellos— no lo admiten.

> ### ⚠ Cambia esa contraseña en cuanto entres
>
> La contraseña es el propio correo, tal y como pediste, pero hay que decirlo
> claro: **ese correo es público** —está en la web, en las propuestas y en la
> firma de cada email— y «usuario = contraseña» es el primer par que prueba
> cualquier ataque automatizado. No hay que adivinar nada: se deduce.
>
> Y es justo la cuenta que lo puede todo: expedientes de clientes, teléfonos,
> contratos y facturación. Datos personales de terceros.
>
> Tampoco cumple la política que el propio sistema exige a los demás usuarios,
> así que el panel te lo recordará en cada acceso hasta que la cambies. Para
> arrancar ya con otra, edita `v_clave` en `02-cuenta-raiz.sql` antes de
> ejecutarlo.

*Si prefieres no crear el usuario por SQL:* Authentication → Users → Add user,
con ese correo y esa contraseña, marcando **Auto Confirm User**; después ejecuta
solo el bloque 2 del archivo.

## Paso 2b · Crear el almacén de archivos

En el editor SQL, pega y ejecuta **`03-almacen.sql`**.

Crea el bucket `documentos`, **privado**: no hay URL pública que se pueda
compartir por accidente. Cada descarga pasa por el token de sesión y por las
mismas reglas de permisos que el resto del sistema — lee quien pueda ver
expedientes, sube quien tenga `exp.docs`, borra quien tenga `exp.borrar`.

Los botones de descarga de documentos del expediente y de recursos de la
Academia tiran de aquí. Mientras no subas ningún archivo, el panel lo dice
—«todavía no tiene archivo subido»— en vez de fingir una descarga.

## Paso 2c · Agentes, contratos y ranking

Pega y ejecuta **`04-mission-contratos.sql`**.

Crea `agentes` y `agente_acciones` (Mission Control), `contratos` (la cartera) y
`ranking_red`. El ranking **no es una tabla**: es una vista calculada a partir
de los contratos firmados, así que no puede discrepar de la realidad ni hay que
mantenerlo a mano.

El webhook de cada agente lleva una restricción que solo admite `https://`, y
vive en la base de datos, no en el HTML, para que no se publique por error.

## Paso 2d · La firma del contrato

Pega y ejecuta **`05-firma-contratos.sql`**.

Añade a `contratos` el token de firma, y tres funciones que son las únicas que
puede tocar un cliente sin cuenta:

- `nuevo_enlace_firma` — la llama el panel. Solo el gestor del contrato o la
  dirección pueden emitir un enlace.
- `contrato_para_firma` — la llama el cliente con su token. Devuelve **solo** su
  contrato y **solo** los campos que necesita el documento: ni el gestor, ni el
  expediente, ni nada de la cartera.
- `firma_contrato` — registra la firma con fecha, hora, IP, navegador y una
  huella SHA-256 del texto exacto que aceptó.

La tabla `contratos` sigue **cerrada a `anon`**. No hay ninguna política que le
deje leerla: lo único que puede hacer son esas dos funciones, y solo con un
token válido, sin usar y sin caducar.

> **Qué validez tiene esa firma.** Es una *firma electrónica simple* (art. 3.10
> del Reglamento eIDAS). Es válida y admisible como prueba, y las evidencias que
> se guardan son justo lo que la sostiene. Pero si el cliente la niega, **la
> carga de demostrar que firmó es vuestra**. Con un prestador cualificado
> (Signaturit, Firmafy, Uanataca) la carga se invierte. Úsala para el día a día;
> para contratos de importe alto, pasa por un prestador. Y que vuestro asesor
> legal revise el circuito antes de estrenarlo con clientes.

## Paso 3 · Desplegar la función de altas

Dar de alta a alguien necesita la clave secreta, así que no puede hacerse desde
el navegador. Esa parte vive en una Edge Function, dentro de Supabase.

```bash
npm install -g supabase
supabase login
supabase link --project-ref ezwhkpfqnzyfulivlows
supabase functions deploy admin-usuarios
```

La función comprueba **primero** quién llama y que sea administrador activo, y
solo entonces usa la clave secreta. `SUPABASE_URL`, `SUPABASE_ANON_KEY` y
`SUPABASE_SERVICE_ROLE_KEY` las inyecta Supabase sola. Añade una más, **obligatoria**,
para cerrar el CORS al dominio del panel:

```bash
supabase secrets set FRONTEND_ORIGIN=https://tudominio.com
```

Sin este paso la función se niega a arrancar (a propósito: sin un origen fijado,
cualquier web podría llamar a una función que da de alta y elimina usuarios). El
botón «Dar de alta usuario» devolverá error hasta que fijes esta variable.

## Paso 4 · Autorizar tu dominio

Authentication → **URL Configuration** → *Site URL* y *Redirect URLs*: añade la
dirección donde publiques el panel en Hostalia. Sin esto, Supabase rechaza los
accesos desde esa web.

---

## El acceso es cerrado

No existe ningún botón de demostración ni forma de entrar sin credenciales. Lo
que se ha quitado va más allá del enlace visible:

- El botón «entrar como administrador» del pie del portal.
- La función que validaba contraseñas **dentro del propio HTML**. Bastaba con
  desactivar Supabase desde el navegador para usarla.
- Las **cinco contraseñas en texto plano** que viajaban en el `index.html`
  publicado, junto con los usuarios de ejemplo.

Ahora el `index.html` no contiene ninguna credencial ni ningún usuario: el
directorio se carga de Supabase después de iniciar sesión. Sin base de datos
disponible, el portal lo dice y no deja pasar a nadie.

## Comprobar que ha funcionado

Sube el ZIP del panel a Hostalia, ábrelo y entra. Deberías ver:

- Bajo la tarjeta de acceso: **«Conectado a Supabase · proyecto ezwhkpfqnzyfulivlows»**
- En *Usuarios y accesos*: tu cuenta con el distintivo **ROOT**
- En *Configuración → Base de datos*: estado **Conectado**, con el botón
  *Probar conexión* que distingue los tres fallos posibles (proyecto
  inalcanzable, esquema sin crear, sesión caducada)

Si algo no cuadra, el panel **no se rompe**: avisa y sigue funcionando con
datos de ejemplo. En *Configuración → Base de datos* puedes revisar la URL y la
clave, o apagar Supabase con un interruptor.

---

## Qué está conectado y qué no

**Conectado a la base de datos:** el acceso, el directorio de usuarios, los
permisos granulares, los estados de cuenta, las altas y bajas, el
restablecimiento de contraseñas, las sesiones abiertas, la bitácora de
auditoría y el registro de accesos de la cuenta de raíz.

**Todavía con datos de ejemplo:** expedientes, presupuestos, academia,
candidatos y el panel principal. Las tablas ya están creadas y con sus
políticas —`expedientes`, `presupuestos`, `candidatos`—, así que es enchufar
cada módulo, no rehacer nada. Dime por cuál quieres seguir.

**Google.** El botón está, pero el acceso federado se activa en Authentication →
Providers → Google, con las credenciales de OAuth de Labs24k. Hasta que lo
hagas, el panel lo dice en vez de fingir que funciona.

---

## Comprobaciones automáticas pasadas

Contra un PostgreSQL real, con el `auth` de Supabase imitado (`_stub-auth.sql`):

- **27** sobre el esquema (`test-esquema.sql`): blindaje de la cuenta de raíz,
  escalada de privilegios, último administrador, bitácora inmutable y RLS por
  rol y por permiso.
- **30** sobre la firma (`test-firma.sql`): quién puede emitir un enlace, qué ve
  el cliente con su token y qué **no**, el rechazo de firmas falsas o enormes,
  la caducidad, el uso único, y que `anon` no tiene acceso a ninguna tabla.

Contra el panel real en un navegador (Playwright), con la CSP de producción:

- **24** sobre el cierre del acceso (`test10.js`).
- **47** sobre usuarios y permisos (`test11.js`).
- **30** sobre la integración con Supabase (`test12.js`).
- **26** sobre informes y descargas (`test13.js`).
- **72** sobre ranking, Mission Control, voz y contratos (`test14.js`),
  incluido el circuito completo de firma de punta a punta: emitir el enlace,
  abrirlo como cliente, dibujar la firma, enviarla y comprobar que el enlace ya
  no sirve.

Y **115** sobre el backend de administración (`backend/test-security.js`).

Todas las pruebas del navegador inician sesión con credenciales reales, porque
ya no queda ningún atajo con el que saltárselo.

---

*Labs24k · Grupo Evolvix Global SL*
