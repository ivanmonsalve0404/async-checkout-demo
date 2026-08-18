# Checkout asíncrono — prueba técnica full stack

Demo de una compra de un solo producto con checkout invitado y asíncrono. La persona usuaria puede revisar el producto, ingresar una tarjeta de prueba, completar la entrega, aceptar dos documentos y confirmar la compra. El servidor es la autoridad para precio, inventario, estado del pago y creación de entrega.

> **Estado verificable a la fecha:** el flujo local usa datos sintéticos y el proveedor `fake`. No hay una URL pública de app/API ni un despliegue cloud aprobado registrado en este repositorio. Por tanto, este README no afirma una publicación HTTPS ni pagos reales. La preparación de Etapa 7 es fail-closed: sin autorización, evidencia same-SHA y entorno protegido, los comandos de nube no deben mutar AWS.

## Índice

- [Objetivo, alcance y límites](#objetivo-alcance-y-límites)
- [Ejecución local](#ejecución-local)
- [Flujo de checkout](#flujo-de-checkout)
- [API y contrato](#api-y-contrato)
- [Arquitectura](#arquitectura)
- [Modelo de datos](#modelo-de-datos)
- [Configuración](#configuración)
- [Calidad y evidencias](#calidad-y-evidencias)
- [UI, accesibilidad y compatibilidad](#ui-accesibilidad-y-compatibilidad)
- [Seguridad](#seguridad)
- [Release, rollback y cleanup](#release-rollback-y-cleanup)
- [Rúbrica, riesgos y autoría](#rúbrica-riesgos-y-autoría)

## Objetivo, alcance y límites

El objetivo es demostrar una experiencia de checkout completa, auditable y segura para una prueba técnica. Incluye una SPA React, una API NestJS, un contrato OpenAPI, pruebas Jest/E2E y una ruta de empaquetado para AWS. El producto semilla es `product-demo-001`; el sistema está diseñado para una unidad por checkout.

| Dentro del alcance                                                                                           | Fuera del alcance o bloqueado de forma explícita                                                                                           |
| ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------ |
| Catálogo de demostración, disponibilidad, cotización en COP, reserva, pago asíncrono, entrega e idempotencia | Cobros de producción, tarjetas reales, autenticación de clientes, múltiples líneas de carrito, devoluciones y conciliación financiera real |
| Adapter local `fake` con 12 resultados deterministas                                                         | Llamadas externas desde el arranque local                                                                                                  |
| Adapter sandbox preparado para una autorización separada                                                     | Activación sandbox sin secreto referenciado, autorización vigente y gate de release                                                        |
| Plantillas y controles de release AWS                                                                        | Declarar un deploy cloud como realizado sin sus evidencias y URLs exactas                                                                  |

Los datos usados en local son sintéticos. No se deben introducir tarjetas reales, datos personales reales ni secretos durante la demostración.

## Ejecución local

### Requisitos

- Node.js `24.19.0` (el rango admitido es `>=24.19.0 <25`).
- pnpm `11.19.0` mediante Corepack.
- Microsoft Edge en Windows, o Chromium de Playwright en otros sistemas, para el smoke E2E local.
- Solo para preparar un release autorizado: AWS CLI v2, OIDC y roles temporales, configurados fuera de Git. No son necesarios para ejecutar la demo local.

### Desde un clon limpio

```powershell
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm verify
pnpm dev
```

Con ambos procesos en marcha, abre estas direcciones locales:

| Superficie                          | Dirección                                                |
| ----------------------------------- | -------------------------------------------------------- |
| Aplicación                          | <http://127.0.0.1:5173/products/product-demo-001>        |
| Salud de compatibilidad             | <http://127.0.0.1:3000/api/health>                       |
| Liveness sin dependencia            | <http://127.0.0.1:3000/api/health/live>                  |
| Readiness de dependencias           | <http://127.0.0.1:3000/api/health/ready>                 |
| Contrato OpenAPI servido por la API | <http://127.0.0.1:3000/api/docs>                         |
| Producto semilla                    | <http://127.0.0.1:3000/api/v1/products/product-demo-001> |

`pnpm dev` usa el adapter `memory`, pagos `fake` y datos de ejemplo. Si el puerto está ocupado, detén el proceso que lo utiliza o cambia el puerto de forma coherente en la configuración local; no expongas el servidor a Internet para esta prueba.

### Comandos cotidianos

| Comando                                     | Qué verifica o produce                                                                                |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `pnpm dev`                                  | API y web locales de desarrollo                                                                       |
| `pnpm seed`                                 | Semilla idempotente del catálogo en el adapter configurado                                            |
| `pnpm lint` / `pnpm typecheck`              | Estilo estático y tipos de todo el workspace                                                          |
| `pnpm test:coverage`                        | Jest de API y web; impone 85 % mínimo en líneas, sentencias, funciones y ramas por aplicación         |
| `pnpm test:contract`                        | OpenAPI, tipos generados y respuestas HTTP de contrato                                                |
| `pnpm test:smoke`                           | Recorridos E2E locales del checkout con el fake; no contacta un origen externo                        |
| `pnpm test:integration`                     | Integración con DynamoDB Local cuando el entorno de prueba lo prepara                                 |
| `pnpm test:e2e:cross-browser`               | Protocolo focal para Chromium, Firefox y WebKit                                                       |
| `pnpm test:a11y` / `pnpm test:perf`         | Automatización de accesibilidad y rendimiento; la revisión humana sigue siendo una evidencia separada |
| `pnpm openapi:lint && pnpm contracts:check` | Consistencia entre OpenAPI y el cliente generado                                                      |
| `pnpm infra:synth`                          | Síntesis local de infraestructura sin desplegar                                                       |
| `pnpm release:build`                        | Paquete inmutable de web, API y worker para un candidato de release                                   |
| `pnpm release:preflight`                    | Revisión fail-closed de autorización, SHA, configuración y evidencia; no despliega                    |
| `pnpm verify`                               | Gate local completo; falla al encontrar un control rojo                                               |

Los comandos de release necesitan los argumentos y archivos temporales descritos en el [contrato de Etapa 7](docs/verification/stage7-contract.md). Si faltan, deben terminar bloqueados y sin tocar la nube; no sustituyas ese bloqueo con valores inventados.

## Flujo de checkout

El diálogo contiene cinco pasos y mantiene el foco dentro de él. Cada transición tiene mensaje de estado para tecnologías asistivas.

1. **Pago:** se valida número de tarjeta, vencimiento, CVC y nombre. La captura es efímera; PAN, vencimiento y CVC no se almacenan en Redux, `localStorage` ni la API propia.
2. **Datos:** se guardan los datos de cliente y dirección mediante el servidor.
3. **Condiciones:** se escoge una cuota y se aceptan por separado términos y tratamiento de datos.
4. **Resumen:** la persona revisa cotización, entrega y condiciones antes de enviar.
5. **Resultado:** se informa `PENDING`, aprobado, declinado o error; se puede consultar el estado sin reenviar el pago.

El backend crea primero una sesión/cotización, reserva inventario al enviar y usa una clave de idempotencia. Un `APPROVED` consume exactamente una reserva y crea una entrega una vez; un `DECLINED`, `ERROR` o `VOIDED` libera la reserva y no crea entrega. Si el proveedor queda incierto, el estado se conserva y el reconciliador decide la transición posterior; el navegador no inventa el resultado.

En local, `FAKE_PAYMENT_SCENARIO` permite reproducir los doce casos `FAKE-E5-01..12` (aprobación, declinación, error, pendiente prolongado, incertidumbre, replay, concurrencia y reloj controlado). No hay un endpoint HTTP para cambiar el escenario.

## API y contrato

La fuente contractual es [OpenAPI canónico](output/architecture/openapi.yaml). Los tipos de TypeScript en [packages/contracts](packages/contracts/src/generated/openapi.d.ts) se generan desde ese archivo; modificar uno sin el otro hace fallar el control de deriva.

| Área      | Operaciones representativas                                                  |
| --------- | ---------------------------------------------------------------------------- |
| Catálogo  | producto, disponibilidad y stock                                             |
| Checkout  | crear sesión, cotizar, guardar cliente/dirección y aceptaciones              |
| Pago      | enviar token opaco, consultar transacción y recuperar un estado seguro       |
| Entrega   | consultar la entrega creada solo tras aprobación                             |
| Operación | `GET /api/health/live`, `GET /api/health/ready`, contrato en `GET /api/docs` |

Las respuestas de error siguen RFC 9457. La API limita el cuerpo JSON, valida origen y payloads, agrega correlación y no entrega al navegador decisiones sensibles como el monto autoritativo o el estado interno del proveedor.

## Arquitectura

### C4 en texto

```text
C1 — Contexto

[Persona compradora]
        │ navegador HTTPS/local
        ▼
[SPA React] ───────────────► [API NestJS]
                                    │
                         ┌──────────┼──────────┐
                         ▼          ▼          ▼
                  [Catálogo] [Checkout] [Proveedor de pago]
                                             (fake local / sandbox autorizado)

C2 — Contenedores

apps/web (React + Redux Toolkit + RTK Query)
        │ contrato HTTP /api/v1
apps/api (NestJS HTTP + casos de uso)
        │ puertos
        ├── memoria / DynamoDB
        ├── fake / sandbox de pago
        └── observabilidad
packages/contracts (OpenAPI → tipos compartidos)
infra (CDK: Data, API, Observability y Web para release autorizado)

C3 — Componentes de la API

HTTP controllers → application/use-cases → domain
                         │                  │
                         └── ports ◄────────┘
                              │
                 infrastructure adapters (persistencia, pagos, logs)
```

Esta separación aplica Ports & Adapters: el dominio no importa React, NestJS, Express ni AWS. Los controladores dependen de casos de uso; los adapters se conectan mediante puertos. El `Result` tipado evita usar excepciones como control de flujo en el dominio y hace explícitas las rutas de error y recuperación.

### Estructura del repositorio

```text
apps/web                 interfaz React y flujo de checkout
apps/api                 API NestJS, dominio, aplicación, puertos y adapters
packages/contracts       tipos generados desde el OpenAPI canónico
infra                    CDK y pruebas de infraestructura
scripts                  contratos, seguridad, smoke, evidencias y controles de release
docs/verification        protocolos, scorecard y trazabilidad de pruebas
output                   arquitectura y reportes/promociones sanitizados
```

## Modelo de datos

El modelo es deliberadamente pequeño y separa la intención de compra de sus efectos:

| Entidad               | Campos/estado relevantes                                                                          | Regla principal                                           |
| --------------------- | ------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| `ProductAvailability` | `productId`, SKU, precio COP, `onHand`, `reserved`, `available`, versión                          | `available = onHand - reserved`; nunca puede ser negativo |
| `Checkout`            | ID, estado, cotización versionada, capability hasheada, cliente/dirección opcionales y expiración | La cotización se calcula en servidor y expira             |
| `Quote`               | producto, subtotal, tarifa, envío, total COP, versión y vencimiento                               | El cliente no fija importes ni moneda                     |
| `Transaction`         | estado de pago, fase de envío, reserva, integridad, intentos, importe y efectos aplicados         | Una clave de idempotencia protege reintentos y doble clic |
| `AcceptanceEvidence`  | versiones/hashes de documentos y fecha de aceptación                                              | Términos y datos personales se aceptan por separado       |
| `Delivery`            | checkout, transacción, destino y estado                                                           | Solo se crea tras un pago aprobado consistente            |

No se persisten PAN, CVC, vencimiento, token de tarjeta crudo ni capability cruda. El navegador conserva únicamente IDs opacos, paso actual y una clave de idempotencia permitida; el servidor almacena el hash de la capability.

## Configuración

Parte desde [.env.example](.env.example). El archivo contiene valores locales no sensibles. Copia únicamente para uso local y no subas `.env` ni secretos.

### Variables locales

| Variable                                                   | Propósito                                                                                         | Clasificación        |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | -------------------- |
| `APP_ENV`                                                  | Selecciona `local`, `test`, `preview` o `assessment`; el validador restringe combinaciones        | Interna              |
| `API_PORT`, `API_BASE_PATH`                                | Puerto y prefijo de la API local                                                                  | Interna              |
| `ALLOWED_ORIGIN`, `PUBLIC_ASSET_ORIGIN`                    | Origen HTTP exacto permitido para la SPA                                                          | Pública/controlada   |
| `DATA_ADAPTER`, `DYNAMODB_ENDPOINT`                        | Elige memoria o DynamoDB Local; los endpoints remotos se rechazan fuera del assessment autorizado | Interna              |
| `CATALOG_TABLE_NAME`, `CHECKOUT_TABLE_NAME`                | Nombres de tablas del adapter                                                                     | Interna              |
| `PRODUCT_SEED_ID`, `PRODUCT_INITIAL_STOCK`                 | Producto y stock sintéticos                                                                       | Pública/controlada   |
| `CHECKOUT_TTL_SECONDS`, `QUOTE_TTL_SECONDS`                | Tiempo de vida de sesión y cotización                                                             | Interna              |
| `PAYMENT_ADAPTER`, `PAYMENTS_ENABLED`, `TOKENIZATION_MODE` | Mantienen el local en `fake`, pagos desactivados y tokenización desactivada                       | Control de seguridad |
| `FAKE_PAYMENT_SCENARIO`, `FAKE_RECONCILE_INTERVAL_MS`      | Seleccionan un escenario fake y su reconciliación local                                           | Solo pruebas         |
| `LOG_LEVEL`                                                | Nivel de log estructurado                                                                         | Interna              |
| `VITE_PRODUCT_ID`                                          | Identificador público del producto para desarrollo                                                | Pública              |

`RUNTIME_SECURITY_ROOT_KEY` y `RUNTIME_SECRET_ARN` **no son valores para versionar**. El primero solo se inyecta fuera de Git cuando DynamoDB lo necesita; el segundo es una referencia ARN a Secrets Manager para el assessment autorizado. El JSON secreto de sandbox, cuando exista, contiene únicamente por nombre: `runtimeSecurityRootKey`, claves pública/privada de prueba, secreto de integridad y los tokens/permalinks de aceptación. No copies valores de ese JSON al README, logs, issues ni evidencias.

La SPA de release carga `public-config.json` de mismo origen con solo `apiBaseUrl` y `productId`; no admite secretos, host remoto ni redirecciones.

## Calidad y evidencias

### Cobertura unitaria con Jest

El requisito de la prueba es superior a 80 %. Este proyecto endurece el mínimo a **85 % en líneas, sentencias, funciones y ramas, tanto en frontend como backend**. La única forma válida de afirmar cobertura para un commit es ejecutar:

```powershell
pnpm test:coverage
```

Los reportes locales se generan en `coverage/api/coverage-summary.json` y `coverage/web/coverage-summary.json`. Son archivos de trabajo: antes de una entrega deben corresponder al SHA exacto revisado y acompañarse de la salida del comando; un reporte heredado no acredita un commit nuevo.

### E2E, contrato y verificación completa

```powershell
pnpm test:contract
pnpm test:smoke
pnpm test:integration
pnpm verify
```

El smoke prueba el flujo con datos sintéticos. Las pruebas de contrato verifican OpenAPI y respuestas HTTP; la integración cubre la persistencia local cuando se habilita su entorno. El [plan de pruebas](docs/verification/test-plan.md), la [trazabilidad](docs/verification/traceability.md) y el [índice de evidencias E6](docs/verification/evidence-index.md) explican qué prueba acredita cada riesgo.

La documentación de Etapa 6 conserva una distinción importante: automatización y pruebas locales no sustituyen una ejecución manual de lector de pantalla ni una evidencia same-SHA. Consulta el [protocolo manual de accesibilidad](docs/verification/manual-accessibility.md) y el [protocolo de compatibilidad, accesibilidad y rendimiento](docs/verification/compatibility-accessibility-performance.md).

## UI, accesibilidad y compatibilidad

La interfaz prioriza comprensión y operación antes que decoración:

- CSS propio con tokens de color, espaciado, radios y tipografía; Grid/Flex para reflow.
- Imagen con `width`, `height`, `aspect-ratio` y `object-fit: cover`, para evitar saltos de layout y desbordes.
- Contenedor de lectura adaptable, `box-sizing: border-box`, títulos con `overflow-wrap` y layout de una sola columna en tamaños pequeños.
- Objetivos interactivos de al menos 44 px, foco visible, enlace “saltar al contenido”, mensajes de estado y errores asociados a los campos.
- Diálogo con foco contenido, Escape que devuelve el foco al invocador, navegación Tab/Shift+Tab y anuncios de cambios asíncronos.
- `prefers-reduced-motion` y `forced-colors` reciben estilos específicos; el color no es el único indicador de estado.

El protocolo automatizado cubre siete viewports (`320×568` a `1440×900`) y tres motores. La revisión humana de teclado, lector de pantalla, zoom 200 % y alto contraste es obligatoria para acreditar accesibilidad; no se infiere de Jest ni axe. Su resultado real debe consultarse en las evidencias de la etapa, no en una afirmación estática de este README.

## Seguridad

- El checkout local no realiza cobros externos. El sandbox solo puede habilitarse con `assessment`, autorización con vencimiento, secreto referenciado y configuración exacta.
- La API recibe un token opaco, no datos de tarjeta crudos; la captura se limpia al avanzar, cerrar o recuperar la sesión.
- Helmet, CORS de origen exacto, cookies `HttpOnly; Secure; SameSite=Strict`, límites de JSON, rate limit, correlación y respuestas RFC 9457 reducen la superficie HTTP.
- El logger aplica allowlist y redacción recursiva; los escáneres rechazan secretos, patrones de tarjeta y valores sensibles sin imprimirlos.
- El frontend valida la configuración pública y la respuesta de producto antes de mostrarla.
- Infraestructura de release: bucket privado, CloudFront/OAC, HTTPS, headers, roles separados y permisos acotados. Su eficacia en un borde público requiere evidencia del despliegue, que aún no está registrada.

Para repetir los controles locales:

```powershell
pnpm security:secrets
pnpm security:dependencies
node scripts/security/validate-workflows.mjs
```

Los controles OWASP/headers son garantías de código y plantilla hasta que un entorno HTTPS autorizado produzca las verificaciones de borde, DAST y smoke post-deploy.

## Release, rollback y cleanup

La ruta de release usa un artefacto construido una vez, checksums y un manifiesto inmutable. Los cuatro stacks previstos separan datos, API, observabilidad y web. Un preflight vuelve a validar candidato, cuenta, región, rol, ventana, presupuesto y aprobación antes de cualquier mutación.

No ejecutes comandos de despliegue, activación, rollback o cleanup solo para “probar”. Requieren una autorización protegida y la evidencia de entrada correcta. El contrato y la lista de evidencias están en:

- [Contrato de Etapa 7](docs/verification/stage7-contract.md)
- [Índice de evidencias de Etapa 7](docs/verification/stage7-evidence-index.md)
- [Plantilla de reporte de release](docs/verification/stage7-release-report.md)

Una release completa solo puede pasar si el gate estricto E6 está en `PASS`, existe un dominio/certificado autorizado, los checks post-deploy pasan y se prueba la vuelta a una release previamente aprobada seguida de re-promoción. Si no hay una release previa verificable, el rollback no se puede marcar como exitoso: se bloquea el gate, no se sustituye con una despublicación.

Para un prerelease, la expiración y el cleanup deben ser recuperables y comprobables antes de exponer cualquier recurso. Bootstrap, datos retenidos y una release previa no se borran como parte del cleanup ordinario. Las URLs solo se añaden al bloque siguiente cuando el manifiesto final validado las provee:

<!-- STAGE7_URLS_START -->

## Entorno desplegado

Sin URL pública registrada. Agregar únicamente URLs HTTPS y el SHA/artefacto correspondiente después de que el manifiesto de Etapa 7 validado acredite el despliegue y sus smokes.

<!-- STAGE7_URLS_END -->

## Rúbrica, riesgos y autoría

### Relación con la evaluación

| Criterio                               | Cómo se revisa sin depender de afirmaciones                                                 |
| -------------------------------------- | ------------------------------------------------------------------------------------------- |
| README completo y correcto             | Este documento, enlaces locales, comandos reproducibles y estado de despliegue honesto      |
| Imágenes rápidas y sin desbordes UI/UX | CSS/markup de producto, pruebas de viewports y reporte de rendimiento same-SHA              |
| Checkout con tarjeta                   | Smoke local, pruebas de componentes, contrato y recorridos approved/failed/pending/recovery |
| API funcional                          | OpenAPI, pruebas de contrato, endpoints de salud y pruebas de integración                   |
| Cobertura FE/BE >80 % con Jest         | `pnpm test:coverage`, umbral 85 % ×4 por aplicación y resúmenes de cobertura del SHA        |
| App y API en cloud                     | URL HTTPS, smoke post-deploy, headers y manifiesto E7; actualmente pendiente/no afirmado    |
| Bonos: OWASP/HTTPS/headers             | Escáneres, controles de código/IaC y evidencia real de borde pendiente de despliegue        |
| Bonos: responsive/navegadores/CSS      | Tokens CSS, reflow, protocolo de 7 viewports y 3 motores                                    |
| Bonos: código limpio, hexagonal y ROP  | Lint, boundaries, Ports & Adapters y `Result` tipado                                        |

El [scorecard](docs/verification/rubric-scorecard.md) es la autoridad para la puntuación: una evidencia faltante, no autorizada o de otro SHA vale cero; los bonos no compensan un criterio base pendiente.

### Riesgos y limitaciones abiertas

1. No existe aún una evidencia de despliegue cloud público ni URLs HTTPS que permitan puntuar el criterio de cloud.
2. El sandbox no es un pago de producción y requiere autorización externa específica; la demo local se mantiene en fake.
3. Métricas de laboratorio no sustituyen Web Vitals de campo; no se afirma telemetría real sin instrumentación y periodo de observación.
4. El cierre de release necesita una release previa aprobada para demostrar rollback real, no solo cierre de publicación.
5. La licencia del repositorio no está declarada mediante un archivo `LICENSE`; hasta añadirla explícitamente, no se concede una licencia de uso más allá de la evaluación acordada.

### Autoría y uso de IA

El historial Git y las revisiones del repositorio son la fuente de autoría y responsabilidad. Este trabajo puede incluir asistencia de OpenAI Codex para análisis, documentación y cambios de código; toda contribución debe ser revisada, validada y asumida por la persona responsable del repositorio. No se usa IA como evidencia de una prueba, un despliegue o una aprobación que no se haya ejecutado realmente.

## Evidencias y documentación relacionada

- [Reporte de Etapa 4](output/etapa-4-fundacion-walking-skeleton.md)
- [Reporte de Etapa 5](output/etapa-5-construccion-vertical-slices.md)
- [Reporte de Etapa 6](output/etapa-6-integracion-verificacion.md)
- [Resultados UAT](docs/verification/uat-results.md)
- [Registro de defectos](docs/verification/defects.md)
- [Entornos y baseline](docs/verification/environments.md)
- [Contratos y configuración](docs/foundation/configuration.md)

Los JSON de runtime, traces, videos y bodies completos no se versionan. Las evidencias promovidas deben contener solo estados, IDs seguros, hashes, métricas y enlaces relativos; nunca tarjetas, tokens, secretos, capacidades crudas, direcciones, correos o teléfonos.
