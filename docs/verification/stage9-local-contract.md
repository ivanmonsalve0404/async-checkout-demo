# Contrato local de Etapa 9

<!-- STAGE9_LOCAL_PREPARATION_ONLY:NO_GATE_AUTHORITY -->

Este contrato prepara la custodia posterior a una aceptación, pero no inicia una
ventana operativa, no consulta red o AWS, no ejecuta pagos o reconciliaciones, no
modifica recursos y no declara ningún gate. La autoridad sigue perteneciendo a la
evidencia ejecutada y a las aprobaciones humanas separadas.

## Entrada única

`stage8-acceptance-handoff.json` es la frontera canónica entre las etapas 8 y 9.
Su schema local es
`scripts/stage9/stage8-acceptance-handoff.schema.json`. Debe demostrar de forma
exacta:

- `GATE-E8-01`, `GATE-E8-02` y `GATE-E8-03` en `PASS`;
- dictamen `ACCEPTED` y estado `READY_FOR_STAGE9`;
- acceptance ID, release ID, runtime SHA, submission SHA y tag;
- igualdad directa de SHAs o autoridad documental exacta, con `fromSha/toSha`, paths
  exclusivamente Markdown, aprobadores separados y hashes raw sellados;
- URLs HTTPS exactas de aplicación, API, documentación, health y repositorio;
- reporte y paquete de E8 ligados por SHA-256;
- los 16 artefactos, 48 evidencias, 32 casos y 72 controles de E8;
- scorecard base 100/100, sin disqualifiers ni riesgos críticos abiertos;
- cero P0/P1 y todos los P2 abiertos aceptados;
- repositorio público, README final, defectos, riesgos y desviaciones aceptados;
- expiry, owner, dashboard, alarmas, budget, runbooks y retención;
- inventario de `PENDING`, incidentes, contactos y ventana propuesta;
- `containsSensitiveData: false`;
- finalización externa de E8 que liga el draft de handoff, los 48 archivos físicos y el
  inventario completo de `ART-ACC-01..16`;
- `handoffSha256` canónico sobre todo el documento salvo ese campo.

El self-test compara el objeto completo de ese schema con el artefacto proveedor
`scripts/stage8/stage8-acceptance-handoff.schema.json`; cualquier deriva rompe la
validación local.

El consumidor compara además el SHA-256 de los bytes originales. Campos extra,
claves duplicadas, URLs de otro origen, ventanas invertidas, un hash re-firmado de
forma incorrecta o cualquier secreto producen rechazo. La entrada ausente o
inválida deriva exclusivamente:

```text
status=NOT_READY
decision=NOT_READY
blocker=BLK-E9-01
GATE-E9-01=NOT_EVALUATED
GATE-E9-02=NOT_EVALUATED
GATE-E9-03=NOT_EVALUATED
```

Una entrada válida sólo produce `READY_FOR_AUTHORIZED_PREFLIGHT`. No produce
`OBSERVING`, `PASS` ni cierre.

## Fuentes canónicas

- `scripts/stage9/catalog.mjs`: 18 artefactos, 44 evidencias, 60 controles,
  siete autorizaciones, tres gates y 34 secciones del reporte.
- `scripts/stage9/stage8-acceptance-handoff.schema.json`: frontera de entrada.
- `scripts/stage9/stage9-closure-plan.schema.json`: plan local no operativo.
- `scripts/stage9/core.mjs`: invariantes puras y render determinista.
- `scripts/stage9/schemas.mjs`: parser estricto y verificación contra schemas.
- `scripts/stage9/self-test.mjs`: pruebas positivas y canarios negativos.
- `scripts/stage9/cli.mjs`: adaptador de sólo lectura/stdout.

Ninguna copia documental redefine esos contratos.

## Modos y estados

El plan separa `charterMode` del modo operativo para resolver la diferencia entre
la carta de la instrucción y su tabla ampliada:

- carta: `INTERVIEW_HOLD`, `LIMITED_OBSERVATION`, `FINAL_DECOMMISSION`;
- operación: los anteriores más `DEMO_ON_DEMAND` y `EVIDENCE_ONLY`;
- preparación local: `NOT_SELECTED`;
- estado inicial: `NOT_STARTED`.

`INTERVIEW_HOLD` siempre usa `route=NONE` y nunca es cierre. Los estados
`BLOCKED_AUTH`, `BLOCKED_EXTERNAL`, `RETURN_TO_STAGE` y `FAILED` tampoco son
cierre.

`CLOSED_RETAINED` exige la ruta `RETAINED`, owner, budget, expiry, plan futuro de
decommission, paquete completo y auditoría final. Los controles de destrucción
deben estar `N-A` con justificación y aprobación; los recursos retenidos deben
estar inventariados. Como `OPSAUD-33` acredita la revocación de accesos temporales,
requiere `AUTH-E9-ACCESS` aprobada. Esta ruta conserva `action=NONE` y rechaza
autoridades aprobadas de destrucción o eliminación de datos: retener nunca autoriza
`AUTH-E9-DESTROY` ni `AUTH-E9-DATA`.

`CLOSED_DECOMMISSIONED` exige la ruta `DECOMMISSIONED`, modo final, rehearsal y
cleanup en `PASS`, cero residuos, coste residual documentado, accesos y datos
tratados, evidencia preservada y las autoridades separadas `AUTH-E9-DESTROY`,
`AUTH-E9-ACCESS` y `AUTH-E9-DATA` aprobadas. Incluso un plan estructuralmente
completo conserva los tres gates en `NOT_EVALUATED`: sólo el ejecutor autorizado
puede emitirlos con evidencia real.

Ambas rutas `CLOSED_*` acreditan observación de dashboards, métricas, logs y costes,
por lo que también requieren `AUTH-E9-OBSERVE` aprobada. La causalidad de
`EVD-OPS-12`, `EVD-OPS-14` y `OPSAUD-30` se declara en `sandboxExecution`: una
verificación exclusivamente de lectura conserva `AUTH-E9-SANDBOX=PENDING` y no la
consume; un smoke o reconciliación mutante exige esa autoridad en `APPROVED`, su
referencia y el hash de la razón. Un cierre que presente esas evidencias sin declarar
una de las dos rutas falla cerrado. `AUTH-E9-ARCHIVE` y `AUTH-E9-RESTORE` conservan
su estado inicial salvo que una acción concreta y separada las necesite.

## Autorizaciones separadas

| Acción                             | Autoridad exacta  |
| ---------------------------------- | ----------------- |
| Observación de métricas/logs/coste | `AUTH-E9-OBSERVE` |
| Sandbox o reconciliación mutante   | `AUTH-E9-SANDBOX` |
| Revocación de accesos              | `AUTH-E9-ACCESS`  |
| Eliminación/anonimización          | `AUTH-E9-DATA`    |
| Destrucción cloud                  | `AUTH-E9-DESTROY` |
| Archivo del repositorio            | `AUTH-E9-ARCHIVE` |
| Restauración para entrevista       | `AUTH-E9-RESTORE` |

Una autoridad aprobada para otra acción nunca satisface la requerida. `DESTROY`
y `ARCHIVE` empiezan `DENIED_BY_DEFAULT`. El CLI no contiene adaptadores para
ejecutar ninguna acción.

## Auditoría y N-A

Los 60 resultados deben conservar el orden `OPSAUD-01..60`. Sólo los controles
que la instrucción publica como `PASS/N-A` aceptan `N-A`:

- `OPSAUD-39` hold con expiry;
- `OPSAUD-41` cambios de emergencia;
- `OPSAUD-44` tratamiento de datos;
- `OPSAUD-49` destrucción autorizada;
- `OPSAUD-50` cleanup IaC;
- `OPSAUD-51` recursos retenidos.

Cada `N-A` requiere razón y referencia de aprobación. Los otros 54 controles son
críticos respecto a `N-A`. `OPSAUD-38` exige `0` en el catálogo y usa el código
de resultado local `ZERO`; los demás controles no opcionales exigen `PASS` para
un candidato de cierre.

## CLI local

Todos los comandos escriben sólo a stdout/stderr. No existe flag de output ni
adaptador de red, AWS, pagos, GitHub o cleanup.

```text
node scripts/stage9/cli.mjs self-test
node scripts/stage9/cli.mjs catalog --format json
node scripts/stage9/cli.mjs catalog --format markdown
node scripts/stage9/cli.mjs validate-intake --input <json-en-workspace>
node scripts/stage9/cli.mjs plan-template --intake <json> --planned-at <UTC>
node scripts/stage9/cli.mjs validate-plan --intake <json> --plan <json>
node scripts/stage9/cli.mjs render-template [--intake <json>]
```

Los inputs deben ser archivos JSON regulares, no symlinks, dentro del workspace y
de hasta 1 MiB. No se resuelven referencias remotas.

## Límite de autoridad

El plan local sólo puede indicar que un candidato tiene una forma coherente y que
una autorización está ligada a su tipo de acción. No demuestra:

- que la autorización sea auténtica fuera del archivo;
- que haya transcurrido la ventana;
- que SPA, API, dashboard, alarmas o coste se hayan observado;
- que una reconciliación, revocación, eliminación o destrucción ocurriera;
- que no queden residuos;
- que el certificado o la comunicación hayan sido firmados.

Por eso el contrato local nunca convierte `INTERVIEW_HOLD`, `BLOCKED_*` o un plan
completo en `GATE-E9-03 = PASS`.
