# Etapa 8 — Contrato local de aceptación

Este documento describe soporte local y fail-closed. No es una ejecución de aceptación, no
prueba acceso público, no autoriza sandbox o AWS y no declara ningún gate aprobado.

## Autoridad de entrada

La evaluación sólo puede pasar de `NOT_READY` a `IN_PROGRESS` cuando el validador recibe
exactamente estas cinco fuentes de una misma ejecución completa de etapa 7:

- `etapa-7-release-despliegue.md`;
- `release-manifest.json`;
- `provenance-ledger.json`;
- `closeout.json`;
- `handoff-payload.json`.

El directorio por sí solo no es una raíz de confianza. También se requiere un
`STAGE8_E7_TRUST_ANCHOR` obtenido por un canal protegido, con los hashes raw esperados del
manifiesto y del cierre, la identidad del release y las cinco URLs. El validador no crea ni
actualiza esta autoridad.

La entrada exige, entre otros controles:

- scope `full`, estado `RELEASED` y modo `VERSIONED_UPDATE`;
- `GATE-E7-01`, `GATE-E7-02` y `GATE-E7-03` en `PASS` en manifiesto, ledger y cierre;
- 20/20 artefactos, 57/57 evidencias y handoff 37/37;
- `runtimeSha = candidateSha`;
- `submissionSha = publication.readmeCommitSha`;
- `runtimeSha = submissionSha` en la ruta normal; o una autoridad
  `STAGE8_DOCUMENTATION_COMMIT_AUTHORITY` autenticada por hash raw y canónico cuando existe un
  commit posterior exclusivamente documental;
- tag inmutable, URLs HTTPS y repositorio publicado;
- hashes raw y hashes canónicos cruzados;
- reporte contractual ejecutado, completo y sin placeholders;
- `nextStage = 8` y `containsSensitiveData = false`.

La ruta documental liga `fromSha` y `toSha`, lista ordenada y única de paths limitada a
`README.md` y `docs/**/*.md`, owner y aprobador distintos, timestamp, razón y hashes raw del
metadata del commit, listado de cambios, aprobación y manifiesto actualizado. El último hash
debe coincidir con los bytes reales del manifiesto recibido. Si falta la autoridad, cambia un
path funcional, se altera cualquier binding o se presenta la autoridad en la ruta de igualdad,
la entrada falla cerrada.

## Catálogos congelados

`scripts/stage8/contract.mjs` exporta catálogos exactos de:

- `ART-ACC-01..16`;
- `EVD-E8-01..48`;
- `ACC-TC-01..32`;
- `ACCAUD-01..72`;
- `GATE-E8-01..03`.

El hash canónico del catálogo se publica con cada estado derivado. Los catálogos son constantes
inmutables; no se obtienen de un assessment ni de una fuente externa.

El assessment ejecutado tiene contrato estructural en
`scripts/stage8/stage8-assessment.schema.json`; el módulo aplica además las reglas semánticas,
el orden exacto de IDs y el hash canónico que JSON Schema no expresa por sí solo.

Cada evidencia distinta de `NOT_STARTED` incluye una ruta relativa normalizada, SHA-256 de sus
bytes, timestamp UTC y owner. Cada caso y control incluye `evidenceIds`; un `PASS` sin al menos
una evidencia causal verificada es inválido. Los casos sólo pueden enlazar `VERIFIED_FULL`; los
controles también pueden enlazar la evidencia formal de un `NOT_APPLICABLE_APPROVED`.

Una pretensión final requiere además `evidenceRoot`. El validador enumera esa raíz local, rechaza
symlinks, aliases, traversal, rutas reservadas, duplicados y archivos extra, lee los 48 archivos
reales, aplica límites de 1 MiB por archivo y 16 MiB en total, escanea secretos y compara bytes,
tamaño y SHA-256. Un `NOT_APPLICABLE_APPROVED` debe resolver a su documento JSON de aprobación
real, ligado a evidencia, release, owner, aprobador y timestamp.

El índice y el paquete inventarían de forma exacta `{id,status,path,rawSha256,bytes}` y fijan su
hash canónico. También contienen el catálogo congelado de bindings `ART-ACC-01..16 → EVD-E8-*`.
La autoridad de evidencia sella ambos hashes; invertir, duplicar o agregar un binding invalida el
material aunque el JSON haya sido re-firmado.

## Estados derivados

El módulo sólo deriva:

- `NOT_READY`: no existe un intake E7 completo, íntegro y confiable;
- `IN_PROGRESS`: el intake es válido, pero la evaluación está ausente, incompleta o bloqueada;
- `REJECTED`: existe fallo, P0/P1, disqualifier o decisión de retorno/rechazo;
- `READY_FOR_FINALIZATION`: la matriz y los bytes físicos son válidos, pero aún no existe
  aceptación final;
- `ACCEPTED`: la autoridad final externa verificó y selló el handoff ya materializado.

El estado predeterminado es `NOT_READY` con `BLK-E8-01`. Un intake válido sin assessment sólo
produce `IN_PROGRESS`. El módulo nunca convierte una ausencia o `BLOCKED_EXTERNAL` en `PASS`.

`READY_FOR_FINALIZATION` requiere simultáneamente 16 artefactos en su estado final, las 48 evidencias en
`VERIFIED_FULL` o `NOT_APPLICABLE_APPROVED`, 32 casos y 72 controles en `PASS`, los tres gates
en `PASS`, base 100/100, confianza alta 6/6, cero P0/P1/disqualifiers/riesgos críticos, P2
aceptados, demo y contingencia, paquete completo, firma de Acceptance Lead y handoff listo.
Además requiere los materiales ligados por una autoridad obtenida mediante canal protegido:

- bytes originales del assessment;
- bytes del índice `STAGE8_EVIDENCE_INDEX`;
- bytes del manifiesto `STAGE8_EVIDENCE_PACKAGE`;
- `STAGE8_EVIDENCE_AUTHORITY`, que fija los hashes raw y canónicos de los tres.

La autoridad liga también acceptance ID, release, emisor y timestamp. Un assessment con SHA
canónico recalculado no puede cambiar el resultado si sus bytes ya no coinciden con esa autoridad.
Si falta cualquiera de esos materiales, una pretensión final deriva `NOT_READY`; nunca queda
como `IN_PROGRESS` o `ACCEPTED` por omisión. En `READY_FOR_FINALIZATION`, la decisión pública es
`REVIEW_REQUIRED`, no `ACCEPTED`, y `GATE-E8-03` permanece `BLOCKED_EXTERNAL`. La finalización
atómica es la única transición que eleva ese gate a `PASS`.

## Handoff a etapa 9

`createStage8HandoffDraft` falla si el estado derivado no es `READY_FOR_FINALIZATION`. Produce
un draft determinista `PENDING_FINAL_AUTHORITY`, todavía no consumible por E9. Una autoridad
externa separada debe ligar los hashes raw y canónicos de assessment, índice, paquete, reporte y
draft, el inventario físico completo de los 16 artefactos, el inventario de 48 evidencias y el
catálogo de bindings. Sólo `finalizeStage8Acceptance` (y el wrapper `createStage8Handoff`) puede
emitir el estado `ACCEPTED` y el handoff `READY_FOR_STAGE9`. El contrato resultante se
documenta en `scripts/stage8/stage8-acceptance-handoff.schema.json` y sella:

- identidad y URLs del release;
- gates E8;
- reporte y paquete final con hashes y conteos;
- scorecard y calidad;
- repositorio público y README final;
- aceptación de defectos, riesgos y desviaciones;
- owner, expiración, dashboard, alarmas y presupuesto;
- runbooks de rollback/cleanup;
- retención, pendientes, incidente, contactos y ventana de cierre;
- hash canónico del handoff.

`ART-ACC-14` se materializa con los bytes del assessment, `ART-ACC-16` con los bytes del índice y
`ART-ACC-15` con los bytes del draft de handoff. Así la autoridad final puede verificarlos sin
que el paquete se autocite ni exista un estado `ACCEPTED` provisional.

El handoff no acepta hashes o conteos declarados por el llamador. Vuelve a leer y validar los
bytes del assessment, índice y paquete contra la autoridad protegida, y deriva de esos bytes los
dos hashes y los cuatro conteos del campo `package`.

El schema no autoriza cleanup, retención, AWS o comunicación externa.

## CLI local

Los comandos sólo leen archivos locales y escriben a stdout/stderr:

```text
node scripts/stage8/cli.mjs self-test
node scripts/stage8/cli.mjs catalog
node scripts/stage8/cli.mjs blocked-report
node scripts/stage8/cli.mjs validate-intake --directory <directorio> --trust-anchor <archivo-json>
node scripts/stage8/cli.mjs assessment-template --directory <directorio> --trust-anchor <archivo-json>
node scripts/stage8/cli.mjs state --directory <directorio> --trust-anchor <archivo-json> --assessment <archivo-json> --evidence-root <directorio> --evidence-index <archivo-json> --evidence-package <archivo-json> --evidence-authority <archivo-json>
node scripts/stage8/cli.mjs report --directory <directorio> --trust-anchor <archivo-json>
node scripts/stage8/cli.mjs report --directory <directorio> --trust-anchor <archivo-json> --assessment <archivo-json> --evidence-root <directorio> --evidence-index <archivo-json> --evidence-package <archivo-json> --evidence-authority <archivo-json>
node scripts/stage8/cli.mjs handoff-draft --directory <directorio> --trust-anchor <archivo-json> --assessment <archivo-json> --evidence-root <directorio> --evidence-index <archivo-json> --evidence-package <archivo-json> --evidence-authority <archivo-json> --report-source <archivo-md> --handoff-metadata <archivo-json>
node scripts/stage8/cli.mjs handoff --directory <directorio> --trust-anchor <archivo-json> --assessment <archivo-json> --evidence-root <directorio> --evidence-index <archivo-json> --evidence-package <archivo-json> --evidence-authority <archivo-json> --report-source <archivo-md> --handoff-metadata <archivo-json> --finalization-authority <archivo-json>
```

No existe opción de output, red, navegador, servidor, AWS, GitHub, sandbox, pago o cleanup.

## Canarios

El self-test es completamente sintético y usa sólo un directorio temporal local que elimina al
terminar. Comprueba:

- intake válido;
- entrada ausente;
- archivo manipulado;
- fuente de otro release;
- paquete manipulado y rehasheado contra un trust anchor inmutable;
- las rutas SHA iguales y SHA distintos con autoridad documental exacta;
- rechazo de ausencia, tamper y path funcional en esa autoridad;
- transición inicial `IN_PROGRESS`;
- derivación sintética `READY_FOR_FINALIZATION`, incluido N/A aprobado, y `REJECTED`;
- ausencia, alteración, intercambio, duplicado, extra y traversal en archivos EVD/ART;
- rechazo `NOT_READY` de una pretensión de aceptación sin autoridad material;
- rechazo de un assessment modificado y re-firmado contra una autoridad ya emitida;
- rechazo de hashes arbitrarios o re-firmados en el paquete, también al crear el handoff;
- reporte bloqueado con 37 secciones;
- imposibilidad de declarar `ACCEPTED` antes de la autoridad final;
- aceptación final positiva y rechazo de autoridad/inventario re-firmados y manipulados.

Resultado esperado: cero llamadas de red y cero mutaciones externas.

## Límites

Este soporte no ejecuta black-box, browsers, sandbox, pruebas, cobertura, accesibilidad,
rendimiento, DAST, cloud, demo o revisión humana. Esas actividades sólo pueden ingresar como un
assessment ejecutado, ligado al release y autorizado conforme a la instrucción de etapa 8.
