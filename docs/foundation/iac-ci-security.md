# Etapa 4 — IaC, CI y seguridad de foundation

Fecha de corte: 2026-08-14. Este documento cubre únicamente `infra/`, `.github/` y `scripts/security/`. La aplicación, los contratos y el package raíz se integran por separado.

## Resultado y límites

| Elemento                                                   | Estado                       | Evidencia                                                 |
| ---------------------------------------------------------- | ---------------------------- | --------------------------------------------------------- |
| CDK base de S3/CloudFront/API/Lambda/DynamoDB/Scheduler    | `IMPLEMENTED`                | `infra/lib/foundation-stack.ts`                           |
| Validación fail-closed de contexto CDK                     | `IMPLEMENTED`                | `infra/lib/config.ts` y tests                             |
| Pruebas de assertions IaC                                  | `PASS_9_OF_9`                | `infra/test/`                                             |
| Síntesis CloudFormation                                    | `PASS_LOCAL_NO_DEPLOY`       | `pnpm infra:synth`                                        |
| CI de PR con permisos mínimos                              | `IMPLEMENTED_NOT_RUN_REMOTE` | `.github/workflows/ci.yml`                                |
| Escaneo, política de workflows y auditoría de dependencias | `PASS_LOCAL`                 | `scripts/security/`                                       |
| Historial Git completo                                     | `NOT_RUN_NO_REPOSITORY`      | ejecutar el escáner con `--history` tras crear/clonar Git |
| Despliegue, bootstrap CDK, creación de roles cloud y OIDC  | `NOT_EXECUTED_UNAUTHORIZED`  | no existen pasos ni workflows de mutación                 |
| Llamadas al proveedor y sandbox                            | `BLOCKED`                    | guardas `fake`, pagos `false`, tokenización `disabled`    |

No se afirma que exista infraestructura en AWS. La salida autorizada de etapa 4 es una plantilla sintetizable, no un despliegue.

## Decisiones aplicadas

### `DEC-E4-INF-01` — Un stack de foundation

Se usa un único `FoundationStack` en lugar de cuatro stacks vacíos. Materializa las fronteras ya aprobadas con menos wiring y se puede separar después por constructos sin cambiar recursos ni contratos. La decisión implementa `ADR-04`, `ADR-05`, `ADR-10`, `ADR-11`, `ADR-13` y `ADR-14` sin agregar VPC, NAT, colas, bus, WAF, dominio o certificados.

### `DEC-E4-INF-02` — Síntesis fake-only con fallo cerrado

El contexto sólo acepta:

- ambiente `preview`;
- adapter `fake`;
- `PAYMENTS_ENABLED=false`;
- tokenización `disabled`;
- región con forma de región AWS; `us-east-1` continúa como supuesto configurable de `ASM-15`.

Sandbox, producción, adapter real, tokenización o pagos habilitados abortan antes de sintetizar. No existen secretos de proveedor ni permisos de Secrets Manager en esta foundation.

### `DEC-E4-INF-03` — Placeholder explícito y no productivo

Las dos Lambdas empaquetan `infra/assets/synth-placeholder/index.js` para que `cdk synth` sea reproducible sin acoplar CDK al output de build de otra tarea. Sólo entrega un health seguro y respuestas sin datos; no contiene negocio, tarjeta, proveedor ni red saliente. Antes de cualquier despliegue autorizado debe sustituirse por el artifact versionado de la aplicación y repetirse todo el gate.

### `DEC-E4-INF-04` — Mutación desactivada

El Scheduler queda `DISABLED` en la plantilla. Los scripts ofrecen `synth`; no ofrecen `deploy`, `destroy` o `bootstrap`. No se modela identidad OIDC porque crear o autorizar roles externos está fuera del alcance concedido.

## Inventario de recursos sintetizados

| Recurso lógico    | Configuración relevante                                                                                          |
| ----------------- | ---------------------------------------------------------------------------------------------------------------- |
| `CatalogTable`    | PK/SK string, on-demand, cifrado AWS administrado, límite 50 RRU/25 WRU, sin PITR mientras `QST-22` siga abierto |
| `CheckoutTable`   | PK/SK string, on-demand, cifrado administrado, TTL físico `purgeAt`, límite 50 RRU/50 WRU                        |
| `GSI1-Reconcile`  | `GSI1PK/GSI1SK`, proyección sólo de cuatro campos aprobados                                                      |
| `GSI2-PendingAge` | `GSI2PK/GSI2SK`, índice escaso por `acceptedAt` para medir todo pago `PENDING`, aun durante backoff              |
| API Lambda        | `nodejs24.x`, ARM64, 512 MiB, 10 s, concurrencia reservada 5, fake-only                                          |
| Worker Lambda     | `nodejs24.x`, ARM64, 512 MiB, 50 s, concurrencia reservada 1, fake-only                                          |
| Log groups        | explícitos, JSON Lambda, retención exacta de 7 días                                                              |
| HTTP API          | route proxy, sin CORS, throttle 5 req/s y burst 10                                                               |
| Scheduler         | cada minuto, input constante sin PII, alias de worker, 2 reintentos acotados, `DISABLED`                         |
| Bucket web        | S3 privado, bloqueo público completo, TLS obligatorio, cifrado administrado, versionado                          |
| CloudFront        | OAC a S3, HTTPS redirect, documentos/API no-store, assets con caché optimizada y price class 100                 |
| Headers           | HSTS, CSP fake-only, deny framing, nosniff y referrer same-origin                                                |

Los nombres globales no están hardcodeados. S3 conserva nombre generado por CloudFormation; las etiquetas cubren proyecto neutral, ambiente, coste, administración y modo fake. El único output es una URL HTTPS no sensible.

## IAM mínimo

No se adjuntan managed policies. Cada Lambda tiene un rol propio; los streams de log usan un wildcard únicamente bajo el ARN de su log group, porque los nombres de stream se crean en runtime.

| Principal      | Acciones                                                        | Recursos                                                       |
| -------------- | --------------------------------------------------------------- | -------------------------------------------------------------- |
| API Lambda     | `logs:CreateLogStream`, `logs:PutLogEvents`                     | sólo su log group                                              |
| API Lambda     | `dynamodb:GetItem`, `BatchGetItem`, `Query`                     | dos tablas y GSI aprobados                                     |
| API Lambda     | `dynamodb:UpdateItem`, `TransactWriteItems`                     | dos tablas                                                     |
| Worker Lambda  | `logs:CreateLogStream`, `logs:PutLogEvents`                     | sólo su log group                                              |
| Worker Lambda  | `dynamodb:GetItem`, `Query`, `UpdateItem`, `TransactWriteItems` | dos tablas y GSI aprobados                                     |
| Scheduler      | `lambda:InvokeFunction`                                         | sólo alias preview del worker                                  |
| CloudFront OAC | lectura de objetos                                              | bucket de origen mediante policy condicionada por distribución |

Las assertions rechazan `Resource: "*"` en policies IAM, Secrets Manager, OIDC y Budget. Un permiso futuro para secretos exige ARNs concretos, autorización de adapter real y nuevo test negativo.

## CI sin autoridad cloud

Los dos workflows usan `permissions: contents: read`, acciones oficiales fijadas a SHA completa, cancelación de ejecuciones obsoletas y timeout por job. No usan `pull_request_target`, contextos `secrets`, claves AWS, `id-token: write` ni `aws-actions/configure-aws-credentials`.

`ci.yml` separa tres resultados bloqueantes:

1. `Metadata`: comprueba archivos esenciales, política de workflows y worktree sin secretos.
2. `Verify`: instala con lockfile congelado y ejecuta el contrato raíz `pnpm verify`.
3. `Summary`: falla salvo que metadata y verificación terminen en success.

`security.yml` usa checkout con historia completa, instala con `--ignore-scripts`, prueba los propios controles, escanea worktree e historial y ejecuta la auditoría de dependencias. Ningún job de PR asume roles ni contacta AWS.

Versiones fijadas:

| Elemento                  | Versión/SHA                                       |
| ------------------------- | ------------------------------------------------- |
| Node                      | `24.19.0`                                         |
| pnpm                      | `11.19.0`                                         |
| TypeScript raíz           | `5.9.3`                                           |
| `aws-cdk-lib`             | `2.265.0`                                         |
| CDK CLI                   | `2.1136.0`                                        |
| `constructs`              | `10.8.1`                                          |
| `actions/checkout`        | `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09` (`v5`) |
| `actions/setup-node`      | `a0853c24544627f65ddf259abe73b1d18a591444` (`v5`) |
| `actions/upload-artifact` | `ea165f8d65b6e75b540449e92b4886f43607fa02` (`v4`) |

Las versiones CDK se consultaron en el registro npm oficial y los SHAs mediante los repositorios oficiales de GitHub el 2026-08-14. El lockfile raíz sigue siendo la autoridad instalada.

`infra/tsconfig.json` hereda `strict=true`. Sólo desactiva `exactOptionalPropertyTypes` dentro del paquete CDK porque las clases concretas de CDK v2 no son asignables a sus propias interfaces con esa opción; no cambia validación de configuración ni código de aplicación. El lock exacto evita que esa excepción derive silenciosamente.

## Controles de seguridad locales

`scan-repository.mjs` usa sólo Node estándar. Recorre archivos de texto, omite dependencias, cachés y cobertura, pero incluye `dist`, `build` y templates `cdk.out` para revisar bundles y CloudFormation. Detecta sin imprimir valores:

- private keys;
- credenciales AWS y tokens GitHub de forma conocida;
- familias de llaves pública/privada/integridad/eventos del proveedor;
- asignaciones de secretos no-placeholder;
- secuencias numéricas de 13–19 dígitos que pasan Luhn.

Con `--history`, revisa el diff completo de todos los commits; si no hay repositorio Git devuelve `BLOCKED` en vez de afirmar un pase. `scan-secrets.mjs` conserva el nombre usado por el contrato raíz. `validate-workflows.mjs` impide permisos de escritura, autoridad cloud, secretos, acciones sin SHA, ausencia de timeouts o concurrencia y triggers peligrosos. Ambos tienen `--self-test`.

Los hallazgos se informan sólo como archivo/línea/regla; nunca se reproduce el valor. Un hallazgo confirmado bloquea, se contiene y sólo se rota con autoridad del propietario.

## Verificación local

```text
node scripts/security/scan-repository.mjs --self-test
node scripts/security/validate-workflows.mjs --self-test
node scripts/security/validate-workflows.mjs
node scripts/security/scan-repository.mjs
pnpm --filter @checkout/infra typecheck
pnpm --filter @checkout/infra test
pnpm --filter @checkout/infra synth
```

Para un repositorio ya inicializado o clonado:

```text
node scripts/security/scan-repository.mjs --history
```

No ejecutar `cdk deploy`, `cdk bootstrap`, `cdk destroy` ni comandos AWS como parte de esta evidencia.

## Branch protection a aplicar cuando exista remoto

Estado actual: `DOCUMENTED_NOT_APPLIED`; configurar remotamente no fue autorizado.

- PR obligatorio a `main`.
- Checks requeridos: `CI / Summary` y `Security / Security`.
- Conversaciones resueltas y al menos una revisión cuando sea viable.
- Force push y borrado de `main` bloqueados.
- Administradores sujetos a los mismos checks cuando la plataforma lo permita.
- Ningún workflow de fork recibe secretos o roles.

## Coste, operación y pendientes

Al no desplegar, el coste causado por esta etapa es USD 0. El modelo documental de etapa 3 para una futura baseline preview permanece en USD 6.01/mes en `us-east-1` asumida, con alertas futuras 5/8/10. No se crea Budget porque requeriría decidir destinatarios y autoridad cloud.

Pendientes antes de cualquier deploy:

1. reemplazar el placeholder por artifacts web/API versionados;
2. autorizar cuenta, región y presupuesto;
3. resolver dominio/certificado, exigir TLS 1.2+ y cerrar acceso directo de execute-api; el certificado CloudFront por defecto no permite fijar esa política;
4. decidir PITR mediante `QST-22`;
5. confirmar CSP/orígenes para la captura elegida, aún bloqueada;
6. habilitar Scheduler sólo con worker real, pruebas de lease y alarmas;
7. añadir secretos por ARN únicamente tras `SPK-02/AUTH-01/AUTH-02`;
8. repetir tests, synth, secret scan, revisión IAM y smoke.

## Trazabilidad de la subtarea

Verificación local con Node 24.19.0 y pnpm 11.19.0:

- typecheck: `PASS`, cero errores;
- tests IaC/config: `PASS`, 9/9;
- synth: `PASS`, una plantilla, cero lookup y cero deploy;
- formato y lint del alcance: `PASS`, cero errores;
- workflows: `PASS`, 2/2 bajo la política estática;
- secret scan: `PASS`, 113 archivos incluyendo `.env.example` y template sintetizado; historia `NOT_RUN_NO_REPOSITORY`;
- auditoría de dependencias productivas: `PASS`, cero vulnerabilidades conocidas;
- template: 2 Lambda `nodejs24.x`, 2 tablas, 2 log groups de 7 días, 1 OAC, 1 distribución y 1 Scheduler deshabilitado;
- template: `Resource: "*"` en IAM = 0; Secrets Manager/OIDC/deploy = 0.

El CLI CDK informó 81 feature flags nuevos sin configuración explícita. El lock fija el comportamiento actual; una actualización futura de CDK debe revisar esos flags mediante change control, no activarlos en masa.

| Tarea        | Artefacto/evidencia                 | Estado                                   |
| ------------ | ----------------------------------- | ---------------------------------------- |
| `FND-36`     | CDK app y stack                     | `IMPLEMENTED`                            |
| `FND-37`     | config e IaC assertions             | `PASS_9_OF_9`                            |
| `FND-38`     | `cdk synth`                         | `PASS_LOCAL_NO_DEPLOY`                   |
| `FND-39`     | CI PR/push                          | `IMPLEMENTED_NOT_RUN_REMOTE`             |
| `FND-40`     | secret/dependency/workflow controls | `PASS_LOCAL_HISTORY_NOT_RUN`             |
| `FND-41`     | template/coverage artifacts 7 d     | `IMPLEMENTED_NOT_RUN_REMOTE`             |
| `ART-FND-08` | `infra/`                            | `SYNTHESIZABLE_LOCAL_PASS`               |
| `ART-FND-09` | `.github/workflows/ci.yml`          | `IMPLEMENTED_NOT_RUN_REMOTE`             |
| `ART-FND-10` | workflows y scripts security        | `PASS_LOCAL_HISTORY_NOT_RUN`             |
| `EVD-E4-11`  | synth                               | `PASS_LOCAL_NO_DEPLOY`                   |
| `EVD-E4-12`  | worktree scan                       | `PASS`; historia `NOT_RUN_NO_REPOSITORY` |
| `EVD-E4-13`  | dependency audit                    | `PASS_ZERO_KNOWN`                        |
| `EVD-E4-15`  | CI remoto                           | `NOT_RUN_NO_REMOTE`                      |

No se eleva `GATE-E4-03` a PASS con evidencias locales parciales.
