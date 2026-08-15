# Configuración y secretos — etapa 4

## Contrato

`apps/api/src/infrastructure/configuration/app-config.ts` valida la configuración al bootstrap con Zod. `apps/web/src/shared/config/public-config.ts` valida las variables públicas durante el build y `infra/lib/config.ts` valida el contexto antes de sintetizar.

La baseline autorizada es:

- `APP_ENV`: `local`, `test` o `preview`;
- `DATA_ADAPTER`: `memory` o DynamoDB exclusivamente en `localhost`/`127.0.0.1`;
- `PAYMENT_ADAPTER=fake`;
- `PAYMENTS_ENABLED=false`;
- `TOKENIZATION_MODE=disabled`;
- orígenes HTTP exactos, sin wildcard;
- rutas API bajo `/api/v1`.

Cualquier valor que parezca habilitar proveedor real, producción, tokenización o DynamoDB remoto aborta. No hay fallback silencioso a un entorno externo.

## Clasificación

| Clase     | Ejemplos de foundation                      | Superficie            |
| --------- | ------------------------------------------- | --------------------- |
| Pública   | ID opaco de producto, origen público local  | build web             |
| Interna   | tablas locales, adapter, nivel de log       | backend/IaC           |
| Secreta   | ninguna necesaria en etapa 4                | fuera del repositorio |
| Prohibida | PAN, CVC, tarjeta, credenciales compartidas | ninguna               |

`.env.example` contiene únicamente valores locales no operativos contra terceros. `.env`, variantes locales, certificados, credenciales y artefactos de autenticación están ignorados.

## Controles

- logger estructurado con allowlist y redacción recursiva;
- escaneo de fuentes, manifests, configuración, builds y CloudFormation;
- escaneo de historia Git cuando el repositorio existe;
- workflows sin contextos `secrets`, OIDC ni credenciales AWS;
- errores HTTP sanitizados mediante RFC 9457;
- respuesta de producto validada en runtime antes del render.

Un hallazgo detiene la entrega. El valor no se imprime; se contiene y sólo se rota o revoca bajo autoridad de su propietario.
