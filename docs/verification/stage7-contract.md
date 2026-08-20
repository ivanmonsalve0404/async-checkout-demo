# Contrato local de Etapa 7

Este contrato prepara una release sin llamar AWS ni cambiar infraestructura. Es
fail-closed: una omisión, un valor adicional, una autorización vencida, una
evidencia inconsistente o un candidato distinto produce error o `NOT_READY`.

## Autoridad de los datos

El archivo de configuración autorizado es un insumo local temporal, no un archivo
para versionar. Debe declarar exactamente:

- autorización aprobada, alcance, responsables, canal, ventana, stacks y criterios
  de aborto;
- cuenta, región y ARN de rol de mínimo privilegio;
- presupuesto máximo aprobado, umbrales y responsables de alertas;
- estrategia de dominio;
- owner y fecha de cleanup, preservando bootstrap y la release anterior;
- solo ARN de referencias de credenciales en Secrets Manager o Parameter Store;
- `containsSensitiveData: false` y ninguna credencial material.

Los alcances válidos son plan no mutante, prerelease efímera y release completa.
Los dos últimos requieren sandbox autorizado y al menos una referencia de
credencial. Una release completa requiere que la entrada de Etapa 6 sea `PASS`;
dominio propio autorizado con TLS 1.2, y una entrada condicional solo habilita la
prerelease no pública autorizada sobre dominio administrado por AWS.

## Interlock de seguridad vigente

Los alcances mutantes permanecen deliberadamente en `NOT_READY` y no solicitan
credenciales AWS mientras falte alguno de estos contratos verificables:

- la release completa necesita un manifiesto inmutable de una versión anterior
  aprobada y un rehearsal real frontend/API `nuevo → anterior → nuevo`; apagar
  y volver a encender el mismo candidato no cuenta como rollback;
- la prerelease necesita un control técnico de acceso que rechace usuarios
  anónimos y cierre el acceso directo al origen API;
- la prerelease necesita una recuperación de expiración durable e idempotente,
  independiente de que el workflow original o una aprobación manual continúen.

El mismo bloqueo existe en el preflight local y en las operaciones directas de
deploy, seed y activación. No puede levantarse mediante un booleano, una URL
difícil de adivinar, `noindex` o evidencia escrita manualmente: cada control debe
tener productor, validador, hash y canarios negativos antes de habilitar cambios.

## CLI local

Todas las órdenes usan `node scripts/stage7/cli.mjs`:

- `self-test` verifica contratos, invariantes, sanitización y documentos;
- `documents` verifica los catálogos y las 33 secciones;
- `build-paths` publica las rutas que debe producir el bundler sin ejecutarlo;
- `config --config <archivo>` valida y muestra únicamente un resumen sanitizado;
- `preflight --config <archivo> --e6-manifest <archivo> [--freeze <archivo>]`
  compara autorización, candidato y estado de entrada sin tocar la nube;
- `freeze --config <archivo> --e6-manifest <archivo> [--tag <tag>] --web <ruta>
--api <ruta> --worker <ruta> --iac <ruta> --public-config <ruta>
--source-artifact-id <id> --source-artifact-sha256 <sha256>
--aws-cli-version <versión> --output <ruta>` crea el manifiesto build-once con
  SHA y checksums. El tag es obligatorio sólo para release completa; una prerelease
  efímera autorizada se congela sin tag final y conserva `GATE-E6-03 = CONDITIONAL_GO`;
- `plan --preflight <archivo> [--output <ruta>]` crea el catálogo inicial sin
  convertir trabajo pendiente en éxito.

El preflight devuelve código 2 cuando la decisión es `NOT_READY`. Los checks de
cuenta, región, trust, bootstrap y cuotas permanecen `NOT_RUN` hasta que el futuro
orquestador cloud los ejecute con autorización explícita. Ningún comando local
declara un gate como aprobado.

### Permisos IAM efectivos

`ART-REL-06` no se satisface con el ARN del rol ni con su trust OIDC. El preflight
AWS protegido debe paginar y leer las políticas inline, administradas, sus versiones
default y el permissions boundary de los roles read, deploy, rollback y cleanup. En
prerelease también audita por separado el rol durable del watchdog de expiración;
este último confía únicamente en el subject de `master` y no comparte permisos con
el cleanup ordinario. El establecimiento cerrado de la baseline añade un sexto rol
`baselineRoleArn`, separado de deploy, con trust exclusivo de
`assessment-release-baseline`; no incorpora DeleteStack, DeleteObject, UpdateAlias
ni CreateInvalidation.

La release completa usa además las variables protegidas
`STAGE7_RELEASE_JOURNAL_CLEANUP_ROLE_ARN` y
`STAGE7_RELEASE_JOURNAL_CLEANUP_PERMISSIONS_BOUNDARY_ARN`, junto con el par dedicado
`STAGE7_RELEASE_RECONCILIATION_RECOVERY_ROLE_ARN` y
`STAGE7_RELEASE_RECONCILIATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN`. Antes de cualquier
mutación, la única sesión OIDC del rol de lectura captura ambos roles y ambos
boundaries: cuatro operaciones role-read sobre cada ARN de rol y dos operaciones
policy-read sobre cada ARN de boundary. Esos cuatro ARN sólo amplían la allowlist de
lectura; no entran en los perfiles mutantes, `roleCount`, `AssumeRole` ni `PassRole`.
Los roles journal y recovery deben tener exactamente cero managed policies adjuntas
y una única política inline igual a su boundary. Se rechazan roles o policies con
wildcard, otra cuenta, recursos intercambiados, condiciones o acciones extra.

La plantilla auxiliar se sintetiza por separado con `pnpm --dir infra synth:authority`
y requiere `STAGE7_AWS_ACCOUNT_ID`, `STAGE7_AWS_REGION` y el ARN exacto del readRole.
El comando no despliega ni modifica AWS: aprovisionar esa plantilla y copiar sus cuatro
outputs a las variables protegidas sigue siendo un prerrequisito externo autorizado.
El assembly del candidato y sus cuatro stacks de release no incorporan este stack IAM,
evitando que una release pueda concederse a sí misma la autoridad que después audita.

El artifact `stage7-aws-auth` contiene exactamente `aws-auth.json`,
`stage7-release-journal-role-effective-permissions.json` y
`stage7-release-reconciliation-recovery-role-effective-permissions.json`.
`aws-auth.json` sella raw/canonical/effective/projection de la autoridad recovery y
raw/effective de journal; la aprobación full repite esos ocho campos. En prerelease
los ocho campos existen en `approval.json` con valor `null`, y los dos archivos de
autoridad están prohibidos. Así un documento de otro alcance no puede reutilizarse
ni aun recalculando sus hashes internos.

Cada grant queda ligado al candidato, configuración, manifiesto, trust, clase de
recurso y contrato versionado del rol. Se rechazan AdministratorAccess,
`NotAction`, `NotResource`, acciones comodín, recursos ajenos al entorno y
capacidades de otro rol. `Resource: "*"` sólo es aceptable en un statement separado
para las acciones exactas que AWS documenta sin resource type; su cantidad y hash
se registran aparte. El inventario global usa `ListStacks` paginado y no devuelve
parámetros ni outputs; cada uno de los cuatro stacks autorizados y `CDKToolkit` se
comprueba además mediante `DescribeStacks` con nombre y ARN concretos en update o
baseline; la prerelease inicial registra esa comprobación como no aplicable antes
de crear sus stacks. Los grants de
`Query` cubren tanto la tabla DynamoDB como su índice, y cada fuente queda ligada por
hash a su nombre o ARN, documento y versión default. La aprobación guarda el hash de
binding del permission set y el SHA-256 del `aws-auth.json`; deployment liga esa
aprobación y el cierre vuelve a validar ambos valores. Hasta ejecutar esa lectura
con la sesión OIDC protegida, el control permanece `NOT_RUN` o `BLOCKED`, nunca
`PASS`.

## Autoridad de seguridad de la prerelease

`prerelease-safety-readiness.json` sustituye el bloqueo preventivo de prerelease
únicamente cuando liga de forma exacta configuración, freeze, ensamblado, plan,
aprobación y `aws-auth.json`. La captura protegida ejecuta tres lecturas GitHub
(`repo`, workflow y ref de la rama default), seguidas de identidad STS y tres
lecturas AWS (`KeyGroup`, `PublicKey` y `DescribeSecret`). Exige que `master`
continúe en el SHA candidato, que el workflow de cleanup exacto esté `active`, que
su blob y cron coincidan y que el modo de acceso, KeyGroup, PublicKey, ARN y
`VersionId` del secreto sean los aprobados. La identidad de lectura incluye
`run_id`, `run_attempt`, clase y prefijo de sesión; el consumidor recompone el ARN
de sesión asumida y todos sus bindings, de modo que una evidencia de otro intento
no es reutilizable.

El readiness es evidencia, no autoridad autosuficiente. Antes de obtener
credenciales mutantes, el job de deploy repite localmente las tres lecturas GitHub;
además, cada deploy, seed, registro de expiración, activación y sandbox vuelve a
consultar esa autoridad inmediatamente antes de STS o de cualquier mutación. Cada
checkpoint registra fase, instante, cantidad de requests, hash de la cabeza de la
rama default y `watchdogLiveAuthoritySha256`. Una respuesta ausente, re-firmada,
stale, de otra fase o intento, una rama avanzada o un watchdog deshabilitado aborta
sin llamadas AWS mutantes.

La activación y el sandbox también producen capturas AWS frescas y no
intercambiables: `prerelease-activation-live-safety-recheck.json` y
`prerelease-sandbox-live-safety-recheck.json`. La primera es obligatoria y se emite
bajo el read role inmediatamente antes de asumir deploy; la segunda se emite bajo
el read role del sandbox inmediatamente antes de ejecutarlo. Seed consume el
checkpoint de los cuatro deploys. Activación consume el ledger prerelease completo.
`EXPIRY_REGISTERED` sólo puede emitirse tras `DescribeStacks` de los cuatro stacks
y la verificación exacta de identidad, outputs y tags `CandidateSha`, `ReleaseId`,
`Environment`, `ExpiresOn` y `CleanupExpiresAtUtc`.

El job `prerelease-safety-readiness` publica el artifact
`stage7-prerelease-safety-readiness`; `external-verification` publica
`stage7-prerelease-live-safety-rechecks`. Cada JSON pasa por
`release:scan -- --pre-upload` antes de publicarse. El recheck de activación siempre
está presente; la ausencia legítima del sandbox opcional se representa omitiendo el
archivo, nunca fabricando evidencia.

## Freeze build-once

El freeze exige candidato limpio, SHA y árbol idénticos a la evidencia aprobada.
La release completa exige tag semántico; la prerelease efímera queda explícitamente
sin tag final. Ambos alcances fijan Node, package manager, CDK y AWS CLI, y exigen
artefactos web, API, worker e IaC ya construidos. Calcula checksum de
cada archivo o árbol, del artefacto CI fuente, lockfile, OpenAPI, cliente generado,
templates y configuración pública. Recompilar después del freeze crea un candidato
distinto: no se puede sustituir silenciosamente el contenido congelado.

Antes de aceptar ese ensamblado, el ejecutor compara la versión local de AWS CLI
con `toolchain.awsCli` del manifiesto. Una versión ausente, ilegible o diferente
aborta; registrar la versión sin comprobarla no satisface el contrato build-once.

El contrato esperado del bundler es:

- `output/release/build/web/**` para assets web;
- `output/release/build/api/index.js` para la Lambda HTTP;
- `output/release/build/worker/index.js` para el reconciliador;
- `output/release/build/iac/**` para templates normalizados.

## README y publicación protegida

Las URLs del dominio autorizado se incorporan al `README.md` antes de congelar el
candidato mediante `pnpm stage7:prepare-readme`, con `STAGE7_CONFIG` apuntando a
la configuración aprobada. Ese cambio se revisa y entra por el flujo normal de PR;
después se vuelve a emitir la evidencia de Etapa 6 para el nuevo SHA. El README no
incluye el SHA ni el tag, evitando una referencia circular imposible de congelar.

La publicación final nunca hace `PUT`, push ni commit directo sobre `master`. Antes
de cualquier escritura consume autorización externa fresca, comprueba con tres
requests contabilizados que aplicación, OpenAPI y readiness respondan 2xx, y
verifica que `master`, el tag y el blob de README coincidan con el candidato. Sólo
entonces crea lo que falte: el GitHub Release y su manifiesto, en ese orden, con
cero, una o dos escrituras. Un reintento verifica lo ya creado, continúa desde el
siguiente elemento y aborta sin sobrescribir ni borrar ante cualquier conflicto.

La URL `.../api` se publica como base del contrato, no como un endpoint de
navegación. Se exige HTTPS, el mismo origen autorizado y el path exacto `/api`;
los probes HTTP 2xx se ejecutan sobre la aplicación, OpenAPI y readiness, sin
inventar una ruta raíz que no forma parte del candidato.

## Ejecución única del smoke sandbox

El job anterior emite `sandbox-execution-request.json` con el esquema estricto de
`scripts/stage7/sandbox-execution-request.schema.json`. El request sólo contiene
identidad pública y límites: repositorio, workflow/ref/SHA, job destino, `run_id`,
`run_attempt`, ambiente, candidato, release, tag aplicable, configuración y el
presupuesto 7/1/1. Su estado es `AWAITING_PROTECTED_APPROVAL`; no contiene
secretos, credenciales, autorizaciones ni autoridad autoemitida. Es el único
artefacto de este protocolo que se publica.

El resumen del job imprime el comentario exacto
`STAGE7_SANDBOX_CLAIM_REQUEST_SHA256=<hash>`. La intervención humana se limita a
revisar el request y pegar ese comentario al aprobar el ambiente protegido de
GitHub. No hay que construir JSON ni calcular hashes. Ya dentro del job aprobado,
`pnpm release:sandbox-claim -- --approve ...` consulta una sola vez la aprobación
de GitHub, exige un único revisor humano y el comentario exacto, y crea el claim
efímero y su recibo como archivos privados 0600 antes de OIDC o secretos del
proveedor.

El claim usa `scripts/stage7/sandbox-execution-claim.schema.json`, dura como máximo
30 minutos y enlaza además los hashes exactos de las autorizaciones de Etapas 6 y
7, owner, revisor y respuesta de aprobación. `executionApprovalSha256` y
`claimId` se derivan de cuerpos canónicos completos. El ejecutor consume el recibo
con creación atómica antes de leer credenciales y revalida el hash del source
después; un segundo consumo falla. Un rerun cambia `run_attempt`, genera un request
nuevo y requiere una aprobación nueva. El request o claim de otro intento o de
otro `run_id` falla antes de credenciales y antes del proveedor.

La referencia enviada a Wompi se deriva de ese mismo binding y deja de usar azar.
Wompi exige que la referencia sea única y rechaza duplicados; esa respuesta es una
segunda barrera, no sustituye el claim ni su consumo atómico. El presupuesto es
exactamente 8 requests: tres lecturas de configuración (incluida la lectura dinámica
inmediata), una tokenización y una creación de transacción, más las lecturas de estado
acotadas del contrato.
Ningún claim, recibo ni dato de tarjeta se publica como artifact.

## Documento final

La plantilla documental y el índice contienen marcadores, no resultados. El
manifiesto final de release es la autoridad única que debe delegar estados,
evidencias, hashes, URLs y gates a las 33 secciones antes del handoff.
