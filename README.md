# Checkout asíncrono — construcción funcional

Aplicación full stack de checkout invitado y asíncrono. La SPA React recorre producto, tarjeta, datos, aceptaciones, resumen y resultado; la API NestJS conserva el estado canónico, coordina inventario, idempotencia, pago y entrega mediante puertos reemplazables.

El alcance ejecutable está cerrado a `fake/local`. El adapter sandbox existe, pero permanece `READY_DISABLED`; no hay llamadas externas, pagos reales, credenciales versionadas ni comandos de despliegue. Usa exclusivamente datos sintéticos.

## Requisitos

- Node.js `24.19.0`.
- pnpm `11.19.0` mediante Corepack.
- Para `test:smoke`: Microsoft Edge instalado en Windows o Chromium de Playwright instalado en otros entornos.

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
- salud API: `http://127.0.0.1:3000/api/health`
- contrato OpenAPI: `http://127.0.0.1:3000/api/docs`
- producto: `http://127.0.0.1:3000/api/v1/products/product-demo-001`

## Comandos principales

| Comando                 | Propósito                                                          |
| ----------------------- | ------------------------------------------------------------------ |
| `pnpm dev`              | inicia API y SPA locales                                           |
| `pnpm seed`             | aplica la semilla idempotente al adapter configurado               |
| `pnpm test:coverage`    | exige 85 % en las cuatro métricas por aplicación                   |
| `pnpm test:contract`    | valida OpenAPI, tipos y respuestas HTTP                            |
| `pnpm test:smoke`       | ejecuta doce recorridos E2E locales sin origen externo             |
| `pnpm infra:synth`      | sintetiza CloudFormation; no despliega                             |
| `pnpm security:secrets` | escanea fuentes, builds y plantilla sintetizada                    |
| `pnpm verify`           | ejecuta el gate local completo y falla ante cualquier control rojo |

## Arquitectura

```text
apps/web                React, Redux Toolkit y RTK Query
apps/api                NestJS, dominio, aplicación, puertos y adapters
packages/contracts      tipos generados desde el OpenAPI canónico
infra                   CDK fake-only sintetizable
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
- El fake implementa doce escenarios deterministas; el adapter sandbox falla cerrado y no abre red sin autorización/configuración explícitas.
- DynamoDB exige una raíz HMAC estable inyectada fuera de Git; sin ella, la API falla antes de iniciar.
- CDK sólo ofrece `synth`; Scheduler permanece deshabilitado.
- Los workflows de pull request tienen `contents: read` y ninguna autoridad AWS.

Los reportes ejecutados están en `output/etapa-4-fundacion-walking-skeleton.md` y `output/etapa-5-construccion-vertical-slices.md`.
