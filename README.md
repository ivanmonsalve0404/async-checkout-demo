# Checkout asíncrono — construcción funcional

Aplicación full stack de checkout invitado y asíncrono. La SPA React recorre producto, tarjeta, datos, aceptaciones, resumen y resultado; la API NestJS conserva el estado canónico, coordina inventario, idempotencia, pago y entrega mediante puertos reemplazables.

El arranque local permanece cerrado a `fake/local`: no hace llamadas externas, no usa credenciales y sólo trabaja con datos sintéticos. El candidato de release incorpora un adapter sandbox y una ruta AWS, pero ambos fallan cerrados salvo que una autorización versionada, el SHA exacto y un entorno protegido habiliten explícitamente la operación. Nunca se habilitan pagos de producción.

## Requisitos

- Node.js `24.19.0`.
- pnpm `11.19.0` mediante Corepack.
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

La configuración segura ya tiene defaults. `.env.example` documenta únicamente valores locales no sensibles; cualquier combinación que intente habilitar pagos externos, tokenización real, producción o DynamoDB no local falla antes de iniciar.

Servicios locales:

- SPA: `http://127.0.0.1:5173/products/product-demo-001`
- vida API: `http://127.0.0.1:3000/api/health/live`
- preparación API: `http://127.0.0.1:3000/api/health/ready`
- compatibilidad heredada: `/api/health` conserva el mismo contrato de preparación
- contrato OpenAPI: `http://127.0.0.1:3000/api/docs`
- producto: `http://127.0.0.1:3000/api/v1/products/product-demo-001`

## Comandos principales

| Comando                                           | Propósito                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------ |
| `pnpm dev`                                        | inicia API y SPA locales                                           |
| `pnpm seed`                                       | aplica la semilla idempotente al adapter configurado               |
| `pnpm test:coverage`                              | exige 85 % en las cuatro métricas por aplicación                   |
| `pnpm test:contract`                              | valida OpenAPI, tipos y respuestas HTTP                            |
| `pnpm test:smoke`                                 | ejecuta doce recorridos E2E locales sin origen externo             |
| `pnpm infra:synth`                                | sintetiza la fundación local/preview; no despliega                 |
| `pnpm release:build`                              | empaqueta una vez web, API y worker para el candidato inmutable    |
| `pnpm stage7:prepare-readme`                      | fija las URLs autorizadas en el README antes de congelar el SHA    |
| `pnpm release:preflight`                          | valida SHA, configuración, evidencia y autorización sin desplegar  |
| `pnpm infra:synth:release`                        | sintetiza los cuatro stacks del release sin mutarlos en AWS        |
| `pnpm infra:synth:publication-recovery-authority` | sintetiza el rol aislado de recuperación; no lo provisiona         |
| `pnpm release:publication-recovery:self-test`     | valida la recuperación idempotente previa a publicación, sin red   |
| `pnpm security:secrets`                           | escanea fuentes, builds y plantilla sintetizada                    |
| `pnpm stage8:self-test`                           | valida el contrato local de aceptación y sus canarios              |
| `pnpm stage8:blocked-report`                      | muestra el estado E8 sin inventar una ejecución pendiente          |
| `pnpm stage9:self-test`                           | valida el contrato local de operación y cierre                     |
| `pnpm stage9:blocked-report`                      | muestra el estado E9 sin iniciar operaciones ni destrucción        |
| `pnpm verify`                                     | ejecuta el gate local completo y falla ante cualquier control rojo |

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

## Release y despliegue

La Etapa 7 usa build-once, checksums y un manifiesto inmutable. El prerelease es efímero, de acceso restringido mediante cookies firmadas, no indexado y de datos sintéticos; sirve para obtener las comprobaciones externas que faltan sin declararlo release público. El release completo exige que el gate estricto de la Etapa 6 esté en `PASS`, dominio y certificados TLS 1.2+, presupuesto aprobado, roles OIDC por operación, rollback probado y cero defectos bloqueantes.

Las credenciales y secretos viven en GitHub Environments, AWS Secrets Manager y variables protegidas. El repositorio sólo conserva referencias y hashes. Los comandos de mutación verifican nuevamente candidato, cuenta, región, rol, ventana y manifiesto antes de cada operación; sin esos datos terminan sin tocar AWS.

<!-- STAGE7_URLS_START -->

## Entorno desplegado

Las URLs finales se publican aquí únicamente después de que smoke 18/18, edge, sandbox, rollback y re-promoción hayan pasado sobre el artefacto exacto.
<!-- STAGE7_URLS_END -->

## Aceptación, operación y cierre

Las Etapas 8 y 9 cuentan con contratos locales verificables y fail-closed. Estos contratos no sustituyen la ejecución real: la Etapa 8 permanece `NOT_READY / BLK-E8-01` hasta recibir la entrega íntegra y anclada de la Etapa 7. Una matriz aprobada sólo produce `READY_FOR_FINALIZATION`; el estado `ACCEPTED` requiere leer los 48 archivos de evidencia, materializar el handoff y validar una autoridad final separada que selle los 16 artefactos. La Etapa 9 permanece `NOT_READY / BLK-E9-01` hasta consumir ese handoff final exacto.

Ningún comando local de estas etapas despliega, publica, abre tráfico, procesa pagos, archiva ni destruye recursos. Las acciones externas y destructivas continúan denegadas por defecto y requieren las autoridades protegidas que define cada contrato.

Los reportes ejecutados están en `output/etapa-4-fundacion-walking-skeleton.md` y `output/etapa-5-construccion-vertical-slices.md`. Las plantillas verificables de las etapas pendientes están en `docs/verification/`.
