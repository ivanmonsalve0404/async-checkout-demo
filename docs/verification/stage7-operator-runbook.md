# Runbook de operación — Etapa 7

Este documento ordena el aprovisionamiento y la ejecución real de la Etapa 7. No es evidencia de que la etapa haya sido ejecutada. Mientras no existan los runs y artefactos protegidos, el estado honesto sigue siendo `NOT_READY`.

## Principios de seguridad

- No crear `AWS_ACCESS_KEY_ID` ni `AWS_SECRET_ACCESS_KEY` en GitHub.
- GitHub usa OIDC y sesiones temporales; el primer aprovisionamiento se realiza por un operador autorizado en AWS.
- No guardar claves Sandbox, tarjetas de prueba, cookies firmadas ni private keys en Git, archivos locales versionados o esta documentación.
- FULL/baseline y PRERELEASE usan regiones y roles distintos. Baseline comparte el target FULL.
- Los dos targets usan dominio controlado y certificados válidos. El modo AWS-managed no satisface el contrato de release.
- Sintetizar una plantilla no la despliega. Toda mutación AWS y toda aprobación de Environment es una acción separada y visible.

## Datos externos que debe aportar el operador

Antes de generar configuraciones se necesitan:

1. SHA final de `master`, con CI verde.
2. ID de cuenta AWS de 12 dígitos.
3. Dos regiones AWS distintas: una para FULL/baseline y otra para PRERELEASE.
4. Zona Route53 controlada, hostnames web/API para ambos targets y sus certificados ACM:
   - certificados web/CloudFront en `us-east-1`;
   - certificado API en la región de cada target.
5. Un runtime JSON secret completo en Secrets Manager por región, con ARN y `VersionId` fijos durante la ventana.
6. Public key y key group de CloudFront para cada target; la private key permanece fuera de GitHub.
7. Correo para Budget/SNS y confirmación humana de la suscripción.
8. Acceso y datos de prueba de Sandbox del proveedor de pagos.
9. Un segundo usuario de GitHub, si se activa revisión obligatoria sin autoaprobación.

## 1. Preparar el candidato local

1. Completar y validar los cambios locales, pero no congelar todavía el SHA final.
2. Elegir los dominios controlados que formarán parte del candidato.
3. Preparar los recursos y configuraciones de las secciones siguientes.
4. No fusionar ni etiquetar hasta incorporar al README las URLs derivadas de la configuración FULL.

## 2. Preparar recursos previos de AWS

Crear o validar, sin exponer sus valores:

- zona Route53 y cuatro hostnames (web/API full y web/API prerelease);
- certificados ACM descritos arriba;
- dos runtime JSON secrets regionales;
- public keys/key groups de CloudFront;
- acceso al correo de alertas.

Cada runtime secret tiene exactamente estas claves, pero sus valores nunca se escriben en el repositorio:

- `runtimeSecurityRootKey`;
- `prereleaseOriginToken`;
- `publicKey`;
- `privateKey`;
- `integritySecret`;
- `termsAcceptanceToken`;
- `termsPermalink`;
- `personalDataAcceptanceToken`;
- `personalDataPermalink`.

Los dos primeros son base64url canónicos; las credenciales y aceptaciones restantes son exclusivamente Sandbox. Un JSON parcial hace que la API falle antes de arrancar. El repositorio no crea secretos ni solicita certificados porque ambas operaciones requieren control humano sobre el dominio y el material sensible.

## 3. Sintetizar y provisionar los dos `CDKToolkit`

Antes de crear nada, comprobar si la cuenta ya contiene el proveedor OIDC de GitHub o un stack `CDKToolkit` en cualquiera de las dos regiones. Si existen, no sobrescribirlos ni adoptarlos a ciegas: exportar su plantilla/configuración y compararlos con el contrato exacto. Una migración o importación de recursos requiere un plan separado.

Configurar las variables de `.env.example` en una terminal temporal. Ejecutar FULL primero:

```powershell
$env:STAGE7_BOOTSTRAP_SCOPE = 'FULL_RELEASE'
$env:STAGE7_INCLUDE_AUXILIARY_READ_AUTHORITY = 'false'
pnpm infra:synth:account-bootstrap
```

La plantilla resultante representa un stack regional llamado `CDKToolkit`, bootstrap v32, y crea también el proveedor OIDC de GitHub. Un operador autorizado debe revisar la plantilla y provisionarla con `CAPABILITY_NAMED_IAM` en la región FULL.

Después cambiar las entradas al target PRERELEASE y ejecutar:

```powershell
$env:STAGE7_BOOTSTRAP_SCOPE = 'PRERELEASE'
$env:STAGE7_INCLUDE_AUXILIARY_READ_AUTHORITY = 'false'
pnpm infra:synth:account-bootstrap
```

Provisionar esa plantilla como `CDKToolkit` en la segunda región. PRERELEASE importa el proveedor OIDC creado por FULL y no lo duplica.

Registrar los outputs de ambos stacks. Los principales son los ARN de read/deploy/rollback/cleanup/baseline, el watchdog prerelease, los roles CDK, bucket/ECR de assets, parámetro de versión y `Stage7GithubOidcProviderArn`.

Esta primera materialización sirve para obtener los ARN estables necesarios para autorizar la configuración y preparar el README. `STAGE7_CANDIDATE_SHA` todavía corresponde al borrador y **no** autoriza ejecutar prerelease ni release. Las policies incluyen rutas ligadas al SHA, por lo que ambos `CDKToolkit` deben actualizarse de nuevo con el SHA final después del merge, como se indica en la sección 5.

## 4. Provisionar autoridades auxiliares

Con los outputs FULL disponibles:

```powershell
$env:STAGE7_AWS_ACCOUNT_ID = '<account-id>'
$env:STAGE7_AWS_REGION = '<full-region>'
$env:STAGE7_AWS_READ_ROLE_ARN = '<Stage7AwsReadRoleArn-output>'
pnpm infra:synth:release-authority
pnpm infra:synth:publication-recovery-authority
```

Revisar y provisionar las plantillas como stacks separados protegidos:

- `checkout-stage7-release-authority`;
- `checkout-stage7-release-successor-publication-recovery-authority`.

Después, volver a sintetizar FULL para incluir las lecturas exactas de esas autoridades:

```powershell
$env:STAGE7_BOOTSTRAP_SCOPE = 'FULL_RELEASE'
$env:STAGE7_INCLUDE_AUXILIARY_READ_AUTHORITY = 'true'
pnpm infra:synth:account-bootstrap
```

Aplicar el cambio revisado al `CDKToolkit` FULL. No habilitar esta opción en PRERELEASE.

## 5. Generar las tres configuraciones

Crear un JSON privado que cumpla [config-authoring-input.schema.json](../../scripts/stage7/config-authoring-input.schema.json). Debe usar exactamente los outputs de AWS, ventanas futuras de menos de 24 horas y referencias a Secrets Manager; nunca valores de secretos. Tanto el archivo como su salida deben permanecer dentro del workspace; `.stage7/private/` está ignorado por Git.

El directorio de salida debe no existir:

```powershell
New-Item -ItemType Directory -Force .stage7\private | Out-Null
# Editar .stage7\private\stage7-authoring-input.json fuera del control de versiones.
pnpm stage7:config:author -- --input .stage7\private\stage7-authoring-input.json --output-directory .stage7\private\generated
```

El comando genera:

- `stage7-full-config.json`;
- `stage7-prerelease-config.json`;
- `stage7-baseline-config.json`;
- un resumen con SHA-256, bytes y mapeo de variables.

Copiar los B64 y SHA exactamente como los emite el autor. No recodificar, reformatear ni agregar salto de línea a los JSON.

Antes de congelar el candidato, incorporar al README las URLs deterministas de la configuración FULL:

```powershell
$env:STAGE7_CONFIG = (Resolve-Path .stage7\private\generated\stage7-full-config.json).Path
pnpm stage7:prepare-readme
git diff -- README.md
```

Revisar ese cambio, incluirlo en el flujo normal de PR y sólo entonces fusionar en `master`. Obtener el SHA final y volver a sintetizar y aplicar **ambos** `CDKToolkit` con ese valor exacto:

```powershell
$env:STAGE7_CANDIDATE_SHA = (git rev-parse HEAD).Trim()
# Repetir la síntesis FULL y aplicarla en la región FULL.
# Cambiar luego todas las entradas al target PRERELEASE,
# repetir la síntesis PRERELEASE y aplicarla en su región.
```

No basta con conservar la plantilla provisional: aunque los ARN sean estables, sus policies deben quedar ligadas al SHA final. Verificar los outputs/readback de las dos actualizaciones antes de copiar variables a GitHub.

Esperar todos los checks del SHA final, ejecutar el [protocolo manual de accesibilidad](manual-accessibility.md) con NVDA o Narrator y regenerar `STAGE6_A11Y_MANUAL_EVIDENCE_B64` para ese SHA exacto. Desde ese momento no modificar el candidato durante prerelease, Stage 6, baseline y release.

## 6. Configurar GitHub

Los ocho Environments protegidos son:

- `assessment-prerelease`;
- `assessment-prerelease-external`;
- `assessment-release`;
- `assessment-release-baseline`;
- `assessment-release-recovery`;
- `assessment-release-reconciliation-recovery`;
- `assessment-release-successor-publication-recovery`;
- `assessment-release-successor-post-success`.

Todos deben permitir sólo `master`.

Los Environments `assessment-prerelease`, `assessment-release-baseline` y `assessment-release` deben tener al menos un reviewer requerido porque el workflow valida una aprobación humana real y exactamente una review aprobada. Mientras `ivanmonsalve0404` sea el único colaborador, puede configurarse como reviewer con **Prevent self-review** desactivado. Si se exige separación de funciones, primero se agrega un segundo colaborador autorizado, se lo configura como reviewer y sólo entonces se activa **Prevent self-review**. Dejar esos Environments sin reviewer hace que el flujo falle cerrado aunque el job pueda comenzar.

Variables estables de repositorio:

- cuenta, regiones, tres configs B64;
- roles FULL/baseline y roles PRERELEASE;
- watchdog PRERELEASE;
- roles/boundaries journal, reconciliation recovery y publication recovery;
- evidencia manual a11y del SHA final.

Secrets por Environment:

- `assessment-prerelease`: `STAGE7_ALERT_EMAIL`;
- `assessment-prerelease-external`: cookies firmadas y los ocho valores Sandbox;
- `assessment-release-baseline`: alerta y cookies baseline;
- `assessment-release`: alerta, smoke inputs y los ocho valores Sandbox.

Las listas exactas de nombres están en `.env.example`. Los valores temporales de autorización se cargan sólo en el Environment y la ventana que corresponden.

## 7. Ejecutar la cadena causal

1. Ejecutar **Stage 7 Conditional Prerelease** para el SHA final.
2. Aprobar el diff IAM, confirmar SNS, cargar las tres autorizaciones externas y aprobar el claim Sandbox.
3. Verificar cleanup del prerelease o su watchdog.
4. Descargar `stage6-authorized-external-evidence` y cargarlo como `STAGE6_EXTERNAL_EVIDENCE_B64`.
5. Reevaluar CI sobre el mismo SHA hasta obtener `GATE-E6-03=PASS`.
6. Ejecutar **Stage 7 Closed Baseline** y conservar run ID, artifact ID/digest y bundle SHA.
7. Crear un tag semántico inmutable sobre ese mismo SHA.
8. Ejecutar **Stage 7 Release** con los identificadores exactos de Stage 6 y baseline.
9. Aprobar diff, alertas/autorizaciones externas y Sandbox cuando el workflow lo solicite.
10. Aprobar el post-success para preservación, closeout y cleanup del journal.

No disparar workflows de recovery preventivamente. Se usan sólo para el estado exacto que sus validadores reconocen.

## 8. Criterio de finalización

Etapa 7 sólo está terminada cuando el run protegido produce y vuelve a validar:

- URLs HTTPS públicas de app, API y Swagger;
- smoke, responsive/cross-browser, a11y, headers/OWASP y Sandbox en PASS;
- rollback y re-promoción en PASS;
- bundle/evidencias y reporte contractual;
- README actualizado por el productor autorizado;
- journals preservados y limpiados con residual cero.

Entonces se materializa la entrada real de Etapa 8. Etapa 8 no puede declarar `ACCEPTED` con plantillas o evidencia local, y Etapa 9 no puede comenzar hasta consumir su handoff final exacto.
