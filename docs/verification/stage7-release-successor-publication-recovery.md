# Recuperación atómica de publicación del sucesor de Etapa 7

Estado local: **IMPLEMENTED / NOT EXECUTED**. La ruta protegida existe y sus contratos pasan
sin red, AWS ni GitHub reales. No se afirma que una recuperación haya ocurrido ni que Etapa 7
esté cerrada.

## P0 cubierto

La recuperación clasifica y sella exactamente una de estas tres ventanas; cualquier mezcla se
rechaza:

- **A — `FENCE_DURABLE_SOURCE_ARTIFACT_MISSING`:** SSM conserva el fence `Version=1`, el job de
  fence terminó `failure|cancelled|timed_out`, no existe su artefacto, publish quedó `skipped` y no
  existe artefacto de publicación.
- **B — `SOURCE_FENCE_PRESENT_PUBLICATION_INCOMPLETE`:** el job y artefacto de fence terminaron
  correctamente; sus bytes deben ser idénticos al valor SSM. Publish terminó
  `failure|cancelled|timed_out` y su artefacto está ausente. La GitHub Release puede existir; el
  adaptador sólo permite verificarla exactamente o crear la parte ausente.
- **C — `SOURCE_PUBLICATION_PRESENT_SUMMARY_INCOMPLETE`:** fence y publish terminaron `success` y
  ambos artefactos exactos existen, pero summary terminó `failure|cancelled|timed_out`. La ruta es
  `VERIFY_EXACT_NOOP`: verifica SSM, los cinco archivos fuente y el estado GitHub vivo sin poder
  mutarlo.

En las tres rutas la conclusión no exitosa del run original permanece inmutable. Nunca se
reescribe SSM ni se fabrica éxito de un job histórico.

## Ruta implementada

Workflow:
`.github/workflows/stage7-release-successor-publication-recovery.yml`.

- Trigger único: `workflow_dispatch` sobre `master`.
- Intento de recuperación único por run: `github.run_attempt == 1`; una repetición es un nuevo
  dispatch y conserva la misma clave idempotente del origen.
- Environment exacto: `assessment-release-successor-publication-recovery`.
- La autoridad separada y su intervalo temporal vigente se validan antes de consultar el run
  origen, instalar dependencias o asumir el rol AWS.
- Concurrencia compartida: `stage7-assessment-release`, sin cancelación en curso.
- Autoridad GitHub físicamente separada: el preflight y toda la ruta C tienen `contents: read`.
  Sólo A/B, después de un plan sellado y vigente, pueden entrar a otro job protegido con
  `contents: write` y `VERIFY_EXACT_OR_CREATE_MISSING`. Ese segundo job no recibe OIDC/AWS.
- Autoridad AWS: rol dedicado y de sólo lectura; el workflow no contiene `PutParameter`,
  `DeleteParameter`, despliegue, rollback ni cleanup.
- Origen observado: repositorio, workflow, branch, SHA, run ID, `run_attempt=1`, conclusión no
  exitosa y la matriz exacta de los jobs fence/publish/summary correspondiente a A, B o C.
- Owner observado: hashes del rol de journal y de su autoridad, ambos ya sellados dentro del
  fence.
- Fence observado: nombre y ARN exactos, `Type=String`, `DataType=text`, `Version=1`, bytes
  exactos y `fenceSha256` esperado.
- Evidencia observada: 27 artefactos previos a publicación, tres internos y un subset contractual
  de cero a dos artefactos incompletos de summary, más exactamente cero/uno artefacto fence y
  cero/uno artefacto publicación según A/B/C. Se pagina el inventario total; nombres desconocidos
  o duplicados bloquean. Sólo los 27 se descargan para reconstruir la evidencia base.
- Reanudación: redescarga los ZIP por ID, verifica cada digest antes de extraer, rehidrata los
  bytes exactos del fence, vuelve a ejecutar todas las validaciones originales de publicación y
  usa el publicador idempotente existente.
- Resultado: dos artefactos exactos por run exitoso de recovery: un ZIP de plan previo a mutación
  con dos basenames raíz y un ZIP result con ocho basenames raíz. Plan y fence deben ser
  byte-idénticos en ambos ZIP; no se admiten prefijos, repack ambiguo, extras ni duplicados. El
  receipt usa el estado
  `PUBLICATION_RECOVERED_PENDING_CLOSEOUT_AUTHORITY`; mantiene
  `sourceRunConclusionUnchanged=true` y `stage7GateClaimed=false`.

La clave de idempotencia depende únicamente de repositorio, run origen, intento origen 1,
candidato, release y fence. No depende del run de recuperación. A/B pueden verificar un tag,
README o release ya creados y crear únicamente la parte ausente; C tiene cero escrituras y carece
físicamente de autoridad `contents: write`.

## Autoridad separada

La variable protegida
`STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY_B64` debe contener un documento
`RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY`, versión 1, con vigencia máxima de 24 horas.
Su basename canónico antes de codificar es
`release-successor-publication-recovery-authority.json`.
Debe enlazar exactamente:

- run origen e intento 1;
- `candidateSha`, `releaseId`, `releaseTag` y `fenceSha256`;
- `crashWindow` exacta A, B o C;
- hashes del owner original del journal;
- hashes del ARN del rol de recuperación y su permissions boundary;
- las seis acciones permitidas para A/B; C excluye explícitamente
  `VERIFY_OR_CREATE_MISSING_GITHUB_PUBLICATION`; las seis acciones prohibidas son invariantes.

El hash canónico del documento se entrega además como input
`recovery_authority_sha256`. Ausencia, expiración, tamper o cambio de identidad abortan antes de
publicar.

## Wiring IAM exacto pendiente en AWS

Este repositorio no crea ni modifica la autoridad real. Antes de ejecutar el workflow se necesita:

1. Variable protegida
   `STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN`.
2. Variable protegida
   `STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN`.
3. Trust OIDC con un único `sub`:
   `repo:ivanmonsalve0404@192544565/async-checkout-demo@1335131225:environment:assessment-release-successor-publication-recovery`
   y `aud=sts.amazonaws.com`.
4. Una única inline identity policy BASE, con nombre exacto
   `stage7-release-successor-publication-recovery-base`, y una permissions boundary cuyo default
   version contiene el mismo BASE. No se permiten managed policies adjuntas ni otra inline policy.
5. El BASE estático permite sólo:
   - `sts:GetCallerIdentity` sobre `*`;
   - `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListRolePolicies` y
     `iam:ListAttachedRolePolicies` sobre el rol dedicado;
   - `iam:GetPolicy` y `iam:GetPolicyVersion` sobre la boundary dedicada;
   - `ssm:GetParameter` sobre
     `/checkout/stage7/release-fence/*`, siempre de sólo lectura.
6. La inline session policy dinámica conserva exactamente las acciones BASE, pero reduce SSM a
   `/checkout/stage7/release-fence/<candidateSha>/<sourceRunId>` sin wildcard. El contrato prueba
   que esta sesión es subconjunto del BASE.

El conjunto completo de variables protegidas consumidas es:

- `STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_ROLE_ARN`;
- `STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_PERMISSIONS_BOUNDARY_ARN`;
- `STAGE7_RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_AUTHORITY_B64`;
- `STAGE7_CONFIG_B64`;
- `STAGE7_EXTERNAL_AUTHORIZATIONS_B64`.

El contrato compara en vivo caller ARN, sesión calculada, trust document, lista completa de inline
y attached policies, identity policy BASE, default boundary document, cuenta, región, rol y recurso
SSM. Cualquier escritura, policy adicional, drift del default version o wildcard distinto de
`sts:GetCallerIdentity` y el subtree SSM read-only del BASE bloquea la ruta.

## Contrato de intake post-success

La publicación recuperable queda resuelta y el contrato incluye el catálogo
`RECOVERY_SUPPLEMENT_CATALOG_V1` y el consumidor `WIRED_CONTRACT`. El plan declara
`POST_SUCCESS_COMPOSITE_REQUIRED`; el intake valida de nuevo
el workflow de recuperación exitoso, el run origen fallido y ambos inventarios. Exige exactamente
dos artefactos paginados del recovery: plan y result, ambos con ID, digest, owner run/attempt 1 y
SHA-256 del ZIP crudo. El ZIP plan contiene sólo fence+plan; result contiene
fence+plan+receipt+cinco archivos de publicación, todos en la raíz. Revalida los bytes duplicados
de plan/fence y todos los enlaces plan/receipt/fence/publicación. Su estado inicial deliberado es
`BLOCKED_CLOSEOUT_AUTHORITY`.

El inventario origen es total, no una búsqueda parcial: 27 artefactos descargables, los tres
artefactos internos exactos, un subset explícito de cero a dos reportes incompletos de summary y
los artefactos route-specific exactos. Duplicados, nombres desconocidos, internos ausentes,
combinaciones A/B/C inválidas o cualquier digest/owner ajeno bloquean la recuperación.

El consumidor histórico sólo aceptaba:

- `workflow_run` del workflow `Stage 7 Release` con `conclusion == success`;
- fence y publicación subidos dentro de ese mismo run.

Un run histórico fallido no puede cambiar de conclusión y GitHub no permite adjuntar nuevos
artefactos a ese run. Por tanto, **no** es válido relajar el `success`, copiar artefactos sin
provenance ni fabricar resultados de jobs.

La integración compartida debe conservar estas reglas:

1. Añadir al catálogo del sucesor un tipo de suplemento de recuperación, no un reemplazo del run
   origen. Debe exigir los dos nombres inmutables con IDs de source/recovery/attempt y el receipt
   hash-bound.
2. Añadir un trigger/consumer dedicado para el workflow de recuperación exitoso. Ese consumidor
   debe reconsultar dos runs: el release origen no exitoso y el recovery exitoso.
3. Validar el run origen con la misma tupla del plan y aceptar únicamente una ventana A/B/C
   exacta, incluidos los tres resultados de job y sus artefactos route-specific.
4. Validar el run de recuperación por workflow path, environment, intento 1, candidato, plan,
   authority, clave idempotente, fence y receipt.
5. Construir una vista compuesta: los 27 artefactos previos provienen del run origen; el result de
   recovery aporta el suplemento canónico de ocho archivos. Los fence/publication originales de
   B/C son validación de provenance y no se vuelven a añadir al bundle final.
6. Recalcular reportes/gates con un estado explícito equivalente a
   `publish-release=success-via-authorized-recovery`; nunca sustituir `needs` por un JSON
   fabricado ni marcar el run original como exitoso.
7. Sólo después, permitir que finalización/preservación consuman la vista compuesta y mantengan
   toda la cadena `{sourceRunId, recoveryRunId, fenceSha256, planSha256, receiptSha256}`.

La autoridad de publicación no incluye la acción
`AUTHORIZE_COMPOSITE_STAGE7_CLOSEOUT_AND_POST_SUCCESS`; esa facultad no puede derivarse ni
suponerse. Hasta que exista y sea validada una
`RELEASE_SUCCESSOR_PUBLICATION_RECOVERY_CLOSEOUT_AUTHORITY`, el intake bloquea el closeout y no
habilita por sí solo el handoff a Etapa 8.

## Archivos y pruebas locales

- Contrato puro:
  `scripts/stage7/release-successor-publication-recovery-contract.mjs`.
- CLI local/workflow:
  `scripts/stage7/release-successor-publication-recovery-cli.mjs`.
- Schema canónico:
  `scripts/stage7/release-successor-publication-recovery.schema.json`.
- Self-test:
  `scripts/stage7/release-successor-publication-recovery-self-test.mjs`.
- Validator dedicado:
  `scripts/security/validate-release-successor-publication-recovery-workflow.mjs`.

La batería cubre determinismo, las matrices A/B/C, route confusion, mismatch fence↔SSM,
mismatch de los cinco archivos de publicación, C con escrituras distintas de cero, source success
incorrecto, jobs incompatibles, SSM Version distinta de 1, tamper de owner/authority, authority
expirada, trust de otro environment, policy extra/attached, boundary drift/escritura, caller ajeno,
inventarios missing/extra/duplicate, ZIP con prefijo o repack y mismatch plan/result. Los tests
realizan cero solicitudes externas y cero mutaciones AWS/GitHub.
