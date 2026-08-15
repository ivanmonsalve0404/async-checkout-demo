# Checkout foundation

Fundación técnica local de una SPA de checkout asíncrono. Esta etapa materializa un recorrido vertical de sólo lectura: React consulta una API NestJS, la API ejecuta un caso de uso y obtiene un producto sembrado mediante un puerto reemplazable.

El alcance está cerrado a `fake/local`. Los pagos están deshabilitados, la tokenización está deshabilitada y no existe ningún comando de despliegue. No uses datos reales, credenciales del proveedor ni endpoints externos.

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

La configuración local segura ya tiene defaults. `.env.example` documenta las únicas variables de foundation; cualquier combinación que habilite pagos, tokenización, producción o DynamoDB no local falla antes de iniciar.

Servicios locales:

- SPA: `http://127.0.0.1:5173/products/product-demo-001`
- salud API: `http://127.0.0.1:3000/api/health`
- contrato OpenAPI: `http://127.0.0.1:3000/api/docs`
- producto: `http://127.0.0.1:3000/api/v1/products/product-demo-001`

## Comandos principales

| Comando | Propósito |
| --- | --- |
| `pnpm dev` | inicia API y SPA locales |
| `pnpm seed` | aplica la semilla idempotente al adapter configurado |
| `pnpm test:coverage` | exige 85 % en las cuatro métricas por aplicación |
| `pnpm test:contract` | valida OpenAPI, tipos y respuestas HTTP |
| `pnpm test:smoke` | ejecuta seis recorridos browser sin origen externo |
| `pnpm infra:synth` | sintetiza CloudFormation; no despliega |
| `pnpm security:secrets` | escanea fuentes, builds y plantilla sintetizada |
| `pnpm verify` | ejecuta el gate local completo y falla ante cualquier control rojo |

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

## Seguridad y límites

- La tarjeta, PAN, CVC, tokens y secretos no se reciben ni persisten.
- El logger aplica allowlist y redacción recursiva; las respuestas usan RFC 9457.
- La SPA valida el payload de producto en runtime antes de renderizarlo.
- El adapter de pagos sólo contiene doce guiones deterministas y nunca abre red.
- CDK sólo ofrece `synth`; Scheduler permanece deshabilitado.
- Los workflows de pull request tienen `contents: read` y ninguna autoridad AWS.

El reporte ejecutado y sus excepciones están en `output/etapa-4-fundacion-walking-skeleton.md`.
