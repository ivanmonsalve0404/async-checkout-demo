# Checkout asíncrono

Aplicación full stack de checkout invitado y asíncrono. La SPA React recorre producto, tarjeta, datos, aceptaciones, resumen y resultado; la API NestJS conserva el estado canónico, coordina inventario, idempotencia, pago y entrega mediante puertos reemplazables.

Repositorio público: [ivanmonsalve0404/async-checkout-demo](https://github.com/ivanmonsalve0404/async-checkout-demo).

La aplicación usa exclusivamente el entorno Sandbox del proveedor de pagos. No admite pagos de producción ni conserva PAN, vencimiento o CVC.

El arranque local permanece cerrado a `fake/local`: no hace llamadas externas, no usa credenciales y sólo trabaja con datos sintéticos. El candidato de release incorpora un adapter sandbox y una ruta AWS, pero ambos fallan cerrados salvo que una autorización versionada, el SHA exacto y un entorno protegido habiliten explícitamente la operación. Nunca se habilitan pagos de producción.

## Requisitos

- Node.js `24.19.0`.
- pnpm `11.19.0` mediante Corepack.
- Docker Engine o Docker Desktop en ejecución; `pnpm verify` lo usa para la integración real con DynamoDB Local.
- Para `test:smoke`: Microsoft Edge instalado en Windows o Chromium de Playwright instalado en otros entornos.
- Para preparar un release autorizado: AWS CLI v2, OIDC y roles temporales configurados fuera del repositorio.

## Arranque desde un clon limpio

```text
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm install --frozen-lockfile
pnpm verify
pnpm dev
```

En Linux, antes de `pnpm verify`, instalar los tres motores usados por la validación igual que CI: `pnpm exec playwright install --with-deps chromium firefox webkit`. En Windows, el smoke local usa Microsoft Edge instalado; Docker Desktop debe estar iniciado en ambos casos cuando corresponda.

La configuración segura ya tiene defaults. `.env.example` documenta únicamente valores locales no sensibles; cualquier combinación que intente habilitar pagos externos, tokenización real, producción o DynamoDB no local falla antes de iniciar.

Servicios locales:

- SPA: `http://127.0.0.1:5173/products/product-demo-001`
- vida API: `http://127.0.0.1:3000/api/health/live`
- preparación API: `http://127.0.0.1:3000/api/health/ready`
- compatibilidad heredada: `/api/health` conserva el mismo contrato de preparación
- contrato OpenAPI: `http://127.0.0.1:3000/api/docs`
- producto: `http://127.0.0.1:3000/api/v1/products/product-demo-001`

## API y documentación

La fuente contractual es [OpenAPI 3.1.2](output/architecture/openapi.yaml). Define 15 operaciones y genera los tipos compartidos de `packages/contracts`.

- Swagger local: `http://127.0.0.1:3000/api/docs`.
- Swagger público: se publica en la sección “Entorno desplegado”.
- Errores: `application/problem+json` conforme a RFC 9457.
- Autoridad: precio, moneda, stock, cotización y estado siempre se calculan en el backend.

La entrega usa Swagger/OpenAPI público como colección ejecutable; no mantiene una colección Postman duplicada.

## Comandos principales

| Comando                                           | Propósito                                                            |
| ------------------------------------------------- | -------------------------------------------------------------------- |
| `pnpm dev`                                        | inicia API y SPA locales                                             |
| `pnpm seed`                                       | aplica la semilla idempotente al adapter configurado                 |
| `pnpm test:coverage`                              | exige 85 % en las cuatro métricas por aplicación                     |
| `pnpm test:contract`                              | valida OpenAPI, tipos y respuestas HTTP                              |
| `pnpm test:smoke`                                 | ejecuta doce recorridos E2E locales sin origen externo               |
| `pnpm infra:synth`                                | sintetiza la fundación local/preview; no despliega                   |
| `pnpm infra:synth:account-bootstrap`              | sintetiza el CDKToolkit/OIDC regional; no lo provisiona              |
| `pnpm infra:synth:release-authority`              | sintetiza las autoridades journal/reconciliation; no las provisiona  |
| `pnpm release:build`                              | empaqueta una vez web, API y worker para el candidato inmutable      |
| `pnpm stage7:config:author`                       | genera configs full, prerelease y baseline desde una entrada sellada |
| `pnpm stage7:prepare-readme`                      | fija las URLs autorizadas en el README antes de congelar el SHA      |
| `pnpm release:preflight`                          | valida SHA, configuración, evidencia y autorización sin desplegar    |
| `pnpm infra:synth:release`                        | sintetiza los cuatro stacks del release sin mutarlos en AWS          |
| `pnpm infra:synth:publication-recovery-authority` | sintetiza el rol aislado de recuperación; no lo provisiona           |
| `pnpm release:publication-recovery:self-test`     | valida la recuperación idempotente previa a publicación, sin red     |
| `pnpm security:secrets`                           | escanea fuentes, builds y plantilla sintetizada                      |
| `pnpm stage8:self-test`                           | valida el contrato local de aceptación y sus canarios                |
| `pnpm stage8:blocked-report`                      | muestra el estado E8 sin inventar una ejecución pendiente            |
| `pnpm stage9:self-test`                           | valida el contrato local de operación y cierre                       |
| `pnpm stage9:blocked-report`                      | muestra el estado E9 sin iniciar operaciones ni destrucción          |
| `pnpm verify`                                     | ejecuta el gate local completo y falla ante cualquier control rojo   |

## Arquitectura

```text
apps/web                React, Redux Toolkit y RTK Query
apps/api                NestJS, dominio, aplicación, puertos y adapters
packages/contracts      tipos generados desde el OpenAPI canónico
infra                   CDK preview y cuatro stacks de release separados
scripts                 contratos, fronteras, seguridad y smoke
output                  arquitectura aprobada y evidencias sanitizadas
```

El dominio no importa NestJS, Express, AWS ni React. Los controladores dependen de casos de uso, no de adapters concretos. `output/architecture/openapi.yaml` es la única fuente contractual; `packages/contracts/src/generated/openapi.d.ts` se regenera y el CI rechaza deriva.

### Ports & Adapters y Railway Oriented Programming

El dominio y la aplicación no dependen de NestJS, Express, AWS ni React. Los casos de uso consumen puertos para catálogo, checkout, proveedor de pagos, contratos, observabilidad y seguridad; los adapters locales, DynamoDB y Sandbox implementan esas fronteras.

Los errores esperables viajan mediante [`Result<T, E>`](apps/api/src/application/result/result.ts), con composición `map`, `mapError`, `andThen` y `andThenAsync`. `pnpm boundaries` impide que dominio o aplicación importen infraestructura.

### Modelo de datos

La persistencia implementada usa dos tablas DynamoDB y dos índices de observación/reconciliación. El detalle de agregados, claves, lifecycle, privacidad e invariantes está en [Modelo de datos](docs/architecture/data-model.md).

## Recorrido local

1. El producto y el stock se consultan al servidor.
2. La API crea una sesión con cotización COP y capability en cookie segura.
3. La SPA captura tarjeta de forma efímera, cliente, entrega y dos aceptaciones.
4. La API reserva inventario y persiste transacción local `PENDING` antes del fake.
5. El frontend consulta el resultado, muestra su estado y vuelve al producto con refetch.

El backend calcula siempre subtotal, tarifa base, envío y total. El navegador no decide monto, moneda, stock ni estado final.

## Escenarios de pago locales

`FAKE_PAYMENT_SCENARIO` selecciona únicamente en el proceso local uno de estos contratos:

- `FAKE-E5-01`: `PENDING` y luego `APPROVED`.
- `FAKE-E5-02`: `PENDING` y luego `DECLINED`.
- `FAKE-E5-03`: `PENDING` y luego `ERROR`.
- `FAKE-E5-04`: `PENDING` prolongado.
- `FAKE-E5-05..08`: incertidumbre, red, protocolo o divergencia.
- `FAKE-E5-09..12`: duplicados, replay, regresión y reloj controlado.

No existe endpoint HTTP para cambiar el escenario y el selector nunca habilita red externa.

## Pruebas y cobertura

Jest exige un mínimo de 85 % —superior al 80 % solicitado— en statements, branches, functions y lines para frontend y backend. El último manifiesto versionado de Etapa 5 registra:

| Aplicación | Suites | Pruebas | Statements | Branches | Functions |   Lines |
| ---------- | -----: | ------: | ---------: | -------: | --------: | ------: |
| API        |  35/35 | 384/384 |    94.92 % |  90.64 % |   98.89 % | 96.23 % |
| Frontend   |  23/23 | 117/117 |    94.06 % |  88.79 % |   95.85 % | 94.74 % |

También se verifican 11 pruebas de integración con DynamoDB Local y 12 recorridos E2E del checkout. La evidencia reproducible está en [verification-manifest.json](output/evidence/stage-5/verification-manifest.json) y se vuelve a calcular para el SHA final.

La correspondencia completa entre los 100 puntos base, los 50 de bonus y su evidencia exigida está en el [scorecard de rúbrica](docs/verification/rubric-scorecard.md); ninguna fila se declara obtenida sin evidencia del mismo SHA.

```text
pnpm test:coverage
pnpm test:contract
pnpm test:smoke
pnpm verify
```

## UI, imágenes y compatibilidad

- El asset principal es un SVG accesible de 639 bytes; el presupuesto es 120 KiB.
- El layout usa tokens CSS, Grid, Flexbox, tamaños fluidos y safe-area insets.
- El runner responsive cubre `320×568`, `375×667`, `390×844`, `667×375`, `768×1024`, `1334×750` y `1440×900`.
- La compatibilidad se ejecuta con Chromium, Firefox y WebKit.
- Se verifican cero overflow horizontal, targets táctiles, navegación por teclado, reduced motion y forced colors.
- La evidencia post-deploy se genera durante la Etapa 7 sobre el mismo artefacto publicado.

## Recuperación e idempotencia

- La capability cruda sólo viaja en cookie `HttpOnly; Secure; SameSite=Strict` y el servidor conserva su hash.
- El navegador persiste únicamente IDs opacos, paso e idempotency key permitidos; nunca tarjeta, token, aceptación o PII.
- El polling consulta estado local y se detiene en finales; un resultado incierto conserva la reserva y bloquea otro `POST`.
- `APPROVED` consume la reserva y crea una entrega exactamente una vez.
- `DECLINED` y `ERROR` liberan la reserva y no crean entrega.
- Los replays con la misma clave/comando devuelven la respuesta aceptada original.

## Seguridad y límites

- PAN, vencimiento y CVC permanecen en el componente efímero del navegador; la API propia sólo recibe un token opaco y no lo persiste.
- El logger aplica allowlist y redacción recursiva; las respuestas usan RFC 9457.
- La SPA valida el payload de producto en runtime antes de renderizarlo.
- El fake implementa doce escenarios deterministas; el adapter sandbox usa tokenización JWE en el navegador y no abre red sin configuración y autorización explícitas.
- DynamoDB exige una raíz HMAC estable inyectada fuera de Git; sin ella, la API falla antes de iniciar.
- El release separa Data, API, Observability y Web; el Scheduler nace deshabilitado y sólo se activa tras web, semilla y autorización.
- Los workflows de pull request tienen `contents: read` y ninguna autoridad AWS.

Controles implementados: Helmet, CSP, HSTS, `X-Content-Type-Options`, `frame-ancestors`, Referrer Policy, Permissions Policy, CORS exacto, cookies seguras, secret scan, dependency audit y CodeQL.

El código fuente no se presenta por sí solo como prueba de HTTPS u OWASP. Los headers reales y el análisis pasivo del target se acreditan únicamente mediante la evidencia autorizada post-deploy.

## Release y despliegue

La Etapa 7 usa build-once, checksums y un manifiesto inmutable. El prerelease es efímero, de acceso restringido mediante cookies firmadas, no indexado y de datos sintéticos; sirve para obtener las comprobaciones externas que faltan sin declararlo release público. El release completo exige que el gate estricto de la Etapa 6 esté en `PASS`, dominio y certificados TLS 1.2+, presupuesto aprobado, roles OIDC por operación, rollback probado y cero defectos bloqueantes.

Las credenciales y secretos viven en GitHub Environments, AWS Secrets Manager y variables protegidas. El repositorio sólo conserva referencias y hashes. Los comandos de mutación verifican nuevamente candidato, cuenta, región, rol, ventana y manifiesto antes de cada operación; sin esos datos terminan sin tocar AWS.

El orden reproducible de aprovisionamiento, variables, aprobaciones y ejecución está documentado en el [runbook de operación de Etapa 7](docs/verification/stage7-operator-runbook.md). La síntesis local no equivale a un despliegue y no abre tráfico.

<!-- STAGE7_URLS_START -->

## Entorno desplegado

Los dominios autorizados se incorporan al candidato antes de congelarlo para que la publicación sea reproducible. Se considerarán enlaces de entrega verificados únicamente después de que smoke 18/18, edge, sandbox, rollback y re-promoción hayan pasado sobre el artefacto exacto.
<!-- STAGE7_URLS_END -->

## Aceptación, operación y cierre

Las Etapas 8 y 9 cuentan con contratos locales verificables y fail-closed. Estos contratos no sustituyen la ejecución real: la Etapa 8 permanece `NOT_READY / BLK-E8-01` hasta recibir la entrega íntegra y anclada de la Etapa 7. Una matriz aprobada sólo produce `READY_FOR_FINALIZATION`; el estado `ACCEPTED` requiere leer los 48 archivos de evidencia, materializar el handoff y validar una autoridad final separada que selle los 16 artefactos. La Etapa 9 permanece `NOT_READY / BLK-E9-01` hasta consumir ese handoff final exacto.

Ningún comando local de estas etapas despliega, publica, abre tráfico, procesa pagos, archiva ni destruye recursos. Las acciones externas y destructivas continúan denegadas por defecto y requieren las autoridades protegidas que define cada contrato.

Los reportes ejecutados están en `output/etapa-4-fundacion-walking-skeleton.md` y `output/etapa-5-construccion-vertical-slices.md`. Las plantillas verificables de las etapas pendientes están en `docs/verification/`.
