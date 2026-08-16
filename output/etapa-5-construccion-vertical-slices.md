# Etapa 5 — Construcción funcional por vertical slices

## 1. Resumen ejecutivo

La construcción funcional quedó verificada en un snapshot local/fake: los 13 slices existen, los 12 escenarios fake y los 12 smokes E2E pasan, frontend y backend superan 85 % en las cuatro métricas y el adapter DynamoDB fue probado contra DynamoDB Local real. La auditoría técnica cerró con cero hallazgos Sev1/Sev2.

No se llamó al sandbox, no se abrió ni modificó el dashboard compartido y no se desplegó a AWS. El adapter sandbox permanece `READY_DISABLED`, su smoke es `NOT_RUN_AUTH_REQUIRED` y `ADR-09`/`API-11` continúan bloqueados.

| Campo | Estado |
| --- | --- |
| Ejecución local/fake | `LOCAL_FAKE_VERIFIED` |
| Slices | 12 `IMPLEMENTED_VERIFIED`; sandbox `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED` |
| Trazabilidad P0 E5 | 99/100 `IMPLEMENTED_VERIFIED`; `RNF-13` pendiente de verificación externa |
| Contrato | 14 paths/operaciones, 251 refs locales, cero drift |
| DynamoDB Local | 1 suite, 10/10 tests, cero AWS externo |
| Sandbox | `READY_DISABLED`; `NOT_RUN_AUTH_REQUIRED` |
| CI del snapshot actual | `PENDING_COMMIT_AND_REMOTE_CI` |
| Gate de salida | `FAIL` por evidencia externa incompleta; sin falla funcional local |

`GATE-E5-01` y `GATE-E5-02` quedan en `PASS`. `GATE-E5-03` no puede usar aún el `CONDITIONAL_GO` estricto: además del sandbox no autorizado falta crear el commit exacto y obtener su CI verde. Tras commit, push y CI verde, la única deuda será el sandbox y el gate podrá pasar a `CONDITIONAL_GO`.

## 2. Estado de entrada y prerrequisitos

| Prerrequisito | Evidencia | Estado |
| --- | --- | --- |
| Diseño UX | `output/etapa-2-diseno-ux-ui.md` | `AVAILABLE` |
| Arquitectura | `output/etapa-3-arquitectura-diseno-tecnico.md` | `AVAILABLE`; integración real bloqueada |
| Fundación | `output/etapa-4-fundacion-walking-skeleton.md` | `APPROVED` |
| `GATE-E4-01/02/03` | Reporte E4 y baseline `6462d30` | `PASS` |
| CI del baseline | Runs registrados en E4 | `GREEN` |
| OpenAPI y tipos | OAS 3.1.2 + `@checkout/contracts` | `GREEN` |
| Fake y semilla | Fundación E4 | `GREEN` |
| Autorizaciones externas | `AUTH-E5-01..05=DENIED`; `AUTH-E5-06=PROHIBITED` | `CONTROLLED` |

Resultado de entrada: `READY_FOR_LOCAL_FAKE_EXECUTION`; `BLK-E5-01` no se activó.

## 3. Baseline y cambios aprobados

- Se conserva Node `24.19.0`, pnpm `11.19.0`, React/Vite/Redux Toolkit/RTK Query, NestJS, ROP, arquitectura hexagonal, DynamoDB por puerto y CDK sin deploy.
- `CHG-17` mantiene el OpenAPI como autoridad y limita la integración real.
- `CHG-E5-01` conserva `ReservationStatus=CONSUMED` y representa incertidumbre con `paymentStatus=PENDING` + `dispatchPhase=UNKNOWN`.
- `ADR-09` permanece bloqueado; no se inventaron URLs, firmas, campos o credenciales del proveedor real.
- Ponytail full mantuvo el alcance en dos adapters, primitivas nativas y dependencias existentes; no se añadieron rutas auxiliares, microservicios ni infraestructura especulativa.

## 4. Plan y trazabilidad de slices

`docs/build/slice-plan.md` contiene las columnas obligatorias de §36 y una matriz atómica de 100 identidades P0 (`32 RF + 23 RNF + 45 AC`).

| Artefacto | Estado local |
| --- | --- |
| `ART-BLD-01` Plan y trazabilidad | `IMPLEMENTED`; aprobación formal pendiente de CI |
| `ART-BLD-02` OpenAPI/tipos | `GREEN` |
| `ART-BLD-03` Catálogo/producto/stock | `IMPLEMENTED` |
| `ART-BLD-04` Sesión y recuperación | `IMPLEMENTED` |
| `ART-BLD-05` Cliente y delivery draft | `IMPLEMENTED` |
| `ART-BLD-06` Cotización/resumen | `IMPLEMENTED` |
| `ART-BLD-07` Contratos/aceptaciones | `IMPLEMENTED` |
| `ART-BLD-08` Tokenización segura | `IMPLEMENTED` |
| `ART-BLD-09` Pago/idempotencia | `IMPLEMENTED` |
| `ART-BLD-10` Fake provider | `GREEN` |
| `ART-BLD-11` Sandbox adapter | `READY_DISABLED` |
| `ART-BLD-12` Polling/reconciliación | `IMPLEMENTED` |
| `ART-BLD-13` Finalización/inventario/entrega | `IMPLEMENTED` |
| `ART-BLD-14` UI de cinco pasos | `DEMONSTRATED` |
| `ART-BLD-15` Suite funcional | `GREEN` |
| `ART-BLD-16` Reporte/handoff | `IMPLEMENTED`; aprobación formal pendiente de CI |

## 5. SLI-E5-01 — Producto y stock

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-01 listProducts`, `API-02 getProduct` y `API-03 getProductStock` están implementadas. Producto, precio y disponibilidad son autoridad del servidor; UI y API cubren carga, retry, 404, stock cero, concurrencia sobre la última unidad y refetch al volver del resultado.

## 6. SLI-E5-02 — Sesión y recuperación

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-04 createCheckout` y `API-05 getCheckout` crean y recuperan la sesión. La capability cruda viaja en cookie HttpOnly y el navegador persiste sólo IDs opacos y datos allowlisted. Se probaron refresh, sesión expirada/inexistente, estado local inválido y recuperación canónica.

## 7. SLI-E5-03 — Cliente y delivery draft

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-06` y `API-07` validan DTO, capability e `If-Match`. Cliente y dirección permanecen como borrador; no crean entrega. La PII se redacta y las respuestas perdidas/412 se recuperan desde el estado canónico sin perder el formulario.

## 8. SLI-E5-04 — Quote y resumen

**Estado:** `IMPLEMENTED_VERIFIED`.

La API crea el quote dentro de la sesión: enteros COP, subtotal y tarifas calculados por backend, versión y expiración. Payloads manipulados se ignoran/rechazan y un quote obsoleto obliga recotización.

## 9. SLI-E5-05 — Contratos y aceptaciones

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-08` entrega dos contratos, permalinks y tokens opacos efímeros. `API-09` exige ambas aceptaciones y persiste sólo evidencia mínima (`acceptedAt` y versiones), nunca tokens de aceptación. Los controles no están preseleccionados.

## 10. SLI-E5-06 — Tokenización

**Estado:** `IMPLEMENTED_VERIFIED` en modo local/fake.

PAN, vencimiento y CVC viven únicamente en el componente efímero. La API propia recibe un token opaco, el token se usa una vez y tarjeta/token quedan fuera de Redux persistido, Web Storage, logs, requests backend, base de datos y evidencia. No se afirma tokenización real/JWE: `ADR-09` sigue bloqueado.

## 11. SLI-E5-07 — PENDING e idempotencia

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-09` hace durable reserva, idempotencia y transacción local `PENDING` antes del primer I/O del provider. Misma key+hash reproduce el mismo 202/Location; hash distinto produce `ERR-10`; otro intento activo produce conflicto. Doble clic, retry, replay y crash entre prepare/dispatch no duplican cargo lógico ni reserva.

## 12. SLI-E5-08 — Fake provider

**Estado:** `IMPLEMENTED_VERIFIED`; artefacto `GREEN`.

El fake implementa el mismo puerto del sandbox y cubre `FAKE-E5-01..12`: approved, declined, error, pending, timeout/unknown, fallas de red/protocolo, divergencia, duplicados, regresión y reloj controlado. No existe endpoint público para seleccionar fixtures y el proceso no abre red externa.

## 13. SLI-E5-09 — Sandbox adapter

**Estado:** `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED`. **Artefacto:** `READY_DISABLED`. **Smoke:** `NOT_RUN_AUTH_REQUIRED`.

El adapter comparte puerto/mappers con el fake y falla cerrado. No contiene credenciales ni activa red con la configuración actual. `AUTH-E5-01/02` siguen `DENIED`, `AUTH-E5-03` impide webhook y `ADR-09`/`API-11` permanecen bloqueados.

## 14. SLI-E5-10 — Polling/reconciliación

**Estado:** `IMPLEMENTED_VERIFIED`.

`API-10` sólo lee estado local. El reconciliador usa backoff `1/2/5/10/15` s, jitter acotado, horario máximo, batch 10, lease 45 s y dedupe entre workers. Maneja 429/5xx/timeout conservando `PENDING` y reserva; recupera autónomamente ventanas `NOT_SENT` y limita llamadas al provider.

## 15. SLI-E5-11 — Finalización aprobada

**Estado:** `IMPLEMENTED_VERIFIED`.

Aprobación finaliza de forma atómica: transacción `APPROVED`, reserva `CONSUMED`, stock decrementado una vez, checkout `PAID` y una entrega. Replays/dos workers no repiten efectos; conflictos de integridad/inventario quedan explícitos. La semántica se verificó en memoria y DynamoDB Local real.

## 16. SLI-E5-12 — Fallos y unknown

**Estado:** `IMPLEMENTED_VERIFIED`.

`DECLINED`, `ERROR` y `VOIDED` liberan una reserva activa sin consumir stock ni crear entrega. Un resultado incierto conserva `paymentStatus=PENDING`, `dispatchPhase=UNKNOWN` y la reserva hasta reconciliación. Divergencias de referencia/monto/moneda no se aceptan como finales.

## 17. SLI-E5-13 — Recovery y UI final

**Estado:** `IMPLEMENTED_VERIFIED`.

El flujo mobile-first de cinco pasos recupera captura, datos, pending, unknown y final desde IDs opacos y estado servidor. El polling es acotado, se detiene en finales y no repite `POST`. Cerrar/reabrir, deep link, sesión expirada y retorno al producto con stock actualizado están cubiertos.

## 18. Contratos/OpenAPI

| Control | Resultado |
| --- | --- |
| Versión | OpenAPI `3.1.2` |
| Paths / operaciones / operationIds / API IDs | `14 / 14 / 14 / 14` |
| `$ref` | `251`; remotas `0` |
| Hash OAS normalizado LF | `aa90d17de283d720ab92112cda8a75ae0663a881cd25da931f56c1148ae4c01a` |
| Tipos generados | `MATCH` |
| Lint, determinismo y drift | `PASS`; drift `0` |
| HTTP contract | `13/13 PASS` |

`API-01..10` y `API-12..14` están implementadas localmente. `API-11 receivePaymentWebhook` permanece `DEFERRED_P1`. El OpenAPI declara fake `GREEN`, sandbox `READY_DISABLED`, red externa `false` y smoke `NOT_RUN_AUTH_REQUIRED`.

## 19. Datos y concurrencia

- Adaptadores in-memory y DynamoDB implementan el mismo puerto.
- DynamoDB Local real (`amazon/dynamodb-local:2.6.1`) ejecutó `1/1` suite y `10/10` tests en endpoint loopback; `awsExternal=false`.
- El digest de imagen registrado es `sha256:1856c05cc66a0e49dc1099e483ad2851477eeebe2135250ac11a1d1227db54b1`.
- Operaciones condicionales/transaccionales cubren reserva, idempotencia, claims/leases, finalización, stock y entrega.
- La raíz HMAC estable se inyecta fuera de Git para DynamoDB; no existe fallback aleatorio persistente.
- Se guardan sólo datos de dominio necesarios y evidencia mínima de aceptación; C4, tokens de pago y provider bodies no se persisten.

## 20. Seguridad y privacidad

- Red ejecutada: loopback; guard de API y canarios de red `PASS`; navegador externo `0`.
- Sandbox/provider externo: `NOT_RUN_AUTH_REQUIRED`.
- PAN/CVC/vencimiento/token en API, storage, DB, logs y evidencia: `0`.
- Logger allowlist, redacción recursiva y RFC 9457 sin payload/stack/PII: `PASS`.
- Errores 400/403/413/415 incluyen `Cache-Control: no-store` y correlación segura.
- Rate limit de pago: burst `2` y refill `2/min`; creación/mutaciones conservan políticas separadas.
- Secret scan de árbol e historial: `PASS`, cero hallazgos confirmados.
- Auditoría de dependencias productivas: `0` high, `0` critical.
- `AUTH-E5-01..05=DENIED`; `AUTH-E5-06=PROHIBITED`.

## 21. Pruebas y cobertura

| Verificación | Resultado |
| --- | --- |
| Workspace, formato, lint y boundaries | `PASS` |
| Typecheck y build | `PASS` |
| OpenAPI/contracts | `PASS`; drift `0` |
| API Jest | `28/28` suites; `338/338` tests |
| API coverage S/B/F/L | `92.80 / 85.81 / 99.10 / 94.60 %` |
| Web Jest | `22/22` suites; `98/98` tests |
| Web coverage S/B/F/L | `94.35 / 90.23 / 88.08 / 93.99 %` |
| DynamoDB Local | `1/1` suite; `10/10` tests |
| Fake | `12/12 PASS` |
| Smoke E2E schema 4 | `12/12 PASS`; exit `0`; guards `PASS` |
| Traceability ejecutable | `38/38`; `36` ejecutables + `2` P1 diferidas |
| CDK synth | `PASS`; sin deploy |
| Secret scan / dependencias | `PASS`; cero findings/high/critical |
| Auditoría técnica final | `0` Sev1/Sev2 abiertos |
| CI remota del snapshot actual | `PENDING_COMMIT_AND_REMOTE_CI` |

El manifiesto `output/evidence/stage-5/verification-manifest.json` liga el snapshot de fuentes, OpenAPI, suites, coverage, DynamoDB Local, smoke y seguridad. Después de cualquier cambio —incluido este reporte— debe regenerarse y `pnpm verify` debe confirmar cero drift.

## 22. Evidencias

| Evidencia | Estado | Referencia |
| --- | --- | --- |
| `EVD-E5-01` | `VERIFIED` | `GATE-E4-03=PASS`; baseline `6462d30` |
| `EVD-E5-02` | `VERIFIED` | `docs/build/slice-plan.md` |
| `EVD-E5-03` | `PASS` | OpenAPI 14/14; hash LF vigente |
| `EVD-E5-04` | `PASS` | Tipos `MATCH`; drift `0` |
| `EVD-E5-05` | `VERIFIED` | Producto/stock y smokes 01/08 |
| `EVD-E5-06` | `VERIFIED` | Sesión creada/recuperada |
| `EVD-E5-07` | `VERIFIED` | Cliente/entrega, 412 y PII |
| `EVD-E5-08` | `VERIFIED` | Quote server-side y stale |
| `EVD-E5-09` | `VERIFIED` | Dos aceptaciones + evidencia mínima |
| `EVD-E5-10` | `VERIFIED` | Cero PAN/CVC en backend |
| `EVD-E5-11` | `VERIFIED` | Token opaco efímero local/fake |
| `EVD-E5-12` | `VERIFIED` | PENDING durable antes de provider |
| `EVD-E5-13` | `VERIFIED` | Misma key/mismo payload |
| `EVD-E5-14` | `VERIFIED` | Misma key/payload distinto |
| `EVD-E5-15..19` | `VERIFIED` | 12 fixtures fake, finales/pending/unknown |
| `EVD-E5-20` | `VERIFIED` | Doble clic/replay sin duplicados |
| `EVD-E5-21` | `VERIFIED` | Aprobación atómica memoria/Dynamo Local |
| `EVD-E5-22` | `VERIFIED` | Release ante fallo |
| `EVD-E5-23` | `VERIFIED` | Cero entregas en fallo |
| `EVD-E5-24` | `VERIFIED` | Refresh durante captura |
| `EVD-E5-25` | `VERIFIED` | Refresh durante PENDING |
| `EVD-E5-26` | `VERIFIED` | Resultado y retorno con stock |
| `EVD-E5-27` | `PASS` | Coverage web/API >=85 % x4 |
| `EVD-E5-28` | `PASS` | Secret/history, redacción y red guards |
| `EVD-E5-29` | `PENDING_COMMIT_AND_REMOTE_CI` | No existe SHA del snapshot sin commit autorizado |
| `EVD-E5-30` | `NOT_RUN_AUTH_REQUIRED` | Sandbox/ADR-09 bloqueados |
| `EVD-E5-31` | `VERIFIED_LOCAL` | 99/100 P0 verified; RNF-13 externo pendiente |
| `EVD-E5-32` | `VERIFIED_LOCAL` | Cero Sev1/Sev2; riesgos externos documentados |

Las evidencias son sintéticas y sanitizadas; no contienen credenciales, tarjeta, tokens de aceptación, direcciones reales ni PII de terceros.

## 23. Trazabilidad

La matriz asigna los 13 slices a las 14 operaciones existentes sin rutas paralelas. El denominador P0 E5 es exactamente `100`: `32 RF + 23 RNF + 45 AC`, sin duplicados.

- `99/100`: `IMPLEMENTED_VERIFIED` mediante pruebas y evidencia local/fake.
- `RNF-13`: `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED`; requiere commit, repositorio/historial visible y CI del snapshot.
- Fuera del denominador: `RF-33=DEFERRED_P1`; `RNF-10/23/24/25/28` mantienen su disposición aprobada.
- Test traceability: `38/38` entradas, selectores existentes; `36` ejecutables y `2` P1 diferidas.
- Operaciones de pago tienen pruebas negativas; estados finales y efectos son idempotentes.

## 24. Riesgos, defectos y deuda

| ID | Estado | Tratamiento/evidencia |
| --- | --- | --- |
| `DEF-E5-01` crash prepare→dispatch | `CLOSED` | Recovery autónomo `NOT_SENT`; cero provider/entrega indebida |
| `DEF-E5-05` ack/lock provider | `CLOSED` | Result validado antes de continuar |
| `DEF-E5-06` polling fijo | `CLOSED` | Backoff, jitter, horario, batch y lease probados |
| `DEF-E5-07` aceptación no persistida | `CLOSED` | `acceptedAt` + versiones mínimas |
| `DEF-E5-08` rate limit | `CLOSED` | Pago 2/min; políticas separadas |
| HTTP RFC9457 cacheable | `CLOSED` | `no-store` verificado en 400/403/413/415 |
| `RSK-E5-01/02/03` duplicidad/stock/entrega | `CONTROLLED` | Idempotencia + condiciones/transacciones + replay |
| `RSK-E5-04/19` fuga C4/PII | `CONTROLLED` | Frontera efímera + allowlists/scans |
| `RSK-E5-07/08/13/16` unknown/reconciliación | `CONTROLLED` | Active hold + backoff/jitter/lease/horario |
| `RSK-E5-10/11/12` provider/URLs/secretos | `BLOCKED_EXTERNAL` | Adapter fail-closed; `ADR-09`; cero red |
| `EXT-E5-01` snapshot sin CI | `OPEN_PROCEDURAL` | Commit+push+checks verdes requeridos |

Defectos funcionales P0/P1 locales abiertos: `0`. La deuda que impide el gate formal es evidencia externa del snapshot, no una excepción funcional.

## 25. Estado de autorizaciones externas

| ID | Estado | Ejecución |
| --- | --- | --- |
| `AUTH-E5-01` | `DENIED` | Cero llamadas sandbox |
| `AUTH-E5-02` | `DENIED` | Cero transacciones sandbox |
| `AUTH-E5-03` | `DENIED` | Cero configuración webhook |
| `AUTH-E5-04` | `DENIED` | Cero acceso al dashboard compartido |
| `AUTH-E5-05` | `DENIED` | Cero despliegue AWS |
| `AUTH-E5-06` | `PROHIBITED` | Cero rotación/2FA |

Sandbox: `READY_DISABLED`; smoke: `NOT_RUN_AUTH_REQUIRED`; `ADR-09` y `API-11`: bloqueados/diferidos. Ninguna limitación se ocultó con fixtures hardcodeados como aprobación.

## 26. Evaluación GATE-E5-01

| Control | Estado |
| --- | --- |
| `SLI-E5-01..05` | `IMPLEMENTED_VERIFIED` |
| Producto/stock server-authoritative | `PASS` |
| Sesión recuperable | `PASS` |
| Cliente/delivery draft | `PASS` |
| Quote server-side | `PASS` |
| Dos aceptaciones + evidencia mínima | `PASS` |
| OpenAPI sin drift | `PASS` |
| Pruebas/secretos/tarjeta | `PASS` |

**Resultado: `GATE-E5-01 = PASS`.**

## 27. Evaluación GATE-E5-02

| Control | Estado |
| --- | --- |
| `SLI-E5-06..12` | `IMPLEMENTED_VERIFIED`; sandbox separado |
| Cero C4 backend/storage | `PASS` |
| PENDING local primero + crash recovery | `PASS` |
| Idempotencia/referencia | `PASS` |
| Fake | `12/12 PASS` |
| Polling/reconciliación | `PASS` |
| Approved/failed/unknown | `PASS` |
| Concurrencia/replay memoria+Dynamo Local | `PASS` |
| Efectos duplicados/entregas fallidas | `0` |

**Resultado: `GATE-E5-02 = PASS`.**

## 28. Evaluación GATE-E5-03

| Umbral | Estado |
| --- | --- |
| Slices obligatorios | 13/13 implementados; sandbox no verificado externamente |
| Artefactos | 16/16 producidos |
| E2E / fake | `12/12` / `12/12 PASS` |
| Coverage web/API >=85 % x4 | `PASS` |
| Lint/typecheck/build/synth | `PASS` local |
| OpenAPI/contract drift | `0` |
| Secret/PAN/CVC/vulnerabilidades | `0` |
| Entregas fallidas/doble efecto/stock negativo | `0` |
| Requisitos P0 sin slice | `0` |
| Defectos P0/P1 funcionales abiertos | `0` |
| Decisiones P0 funcionales abiertas | `0`; `ADR-09` externa bloqueada |
| `EVD-E5-29` / SHA exacto / CI remota | `PENDING_COMMIT_AND_REMOTE_CI` |
| Sandbox smoke | `NOT_RUN_AUTH_REQUIRED` |

**Resultado: `GATE-E5-03 = FAIL — PENDING_COMMIT_AND_REMOTE_CI`.**

El resultado no señala una brecha funcional local. La taxonomía de §37.3 no permite `CONDITIONAL_GO` mientras existan dos deudas: CI del snapshot y sandbox. Tras crear un commit autorizado, publicar la rama y obtener CI verde para ese SHA, `EVD-E5-29` podrá pasar; entonces la única deuda será el sandbox y el resultado exacto será `CONDITIONAL_GO`, habilitando etapa 6. Si la CI falla, el gate permanece `FAIL`.

## 29. Handoff a etapa 6

**Estado:** `BLOCKED_PENDING_COMMIT_AND_REMOTE_CI`.

| # | Entrega requerida | Estado |
| ---: | --- | --- |
| 1 | Commit SHA exacto | `PENDING`; el hash de snapshot no sustituye un SHA Git |
| 2 | Instalación, seed, start y verify | README: `pnpm install --frozen-lockfile`, `pnpm seed`, `pnpm dev`, `pnpm verify` |
| 3 | OpenAPI y cliente generado | `GREEN`; hash LF y tipos `MATCH` |
| 4 | Matriz de trazabilidad | Disponible; 100 filas P0 |
| 5 | Lista de 13 slices/estado | 12 verified + sandbox not externally verified |
| 6 | Fake scenarios/selector | 12/12; selector sólo por entorno local/test |
| 7 | Fixtures contractuales | Disponibles; cero red |
| 8 | Habilitación sandbox | Documentada sin secretos; bloqueada por `ADR-09`/AUTH |
| 9 | `AUTH-E5-*` | Denied/prohibited registrados |
| 10 | IDs sandbox | `NOT_RUN_AUTH_REQUIRED`; ninguno creado |
| 11 | E2E y 12 smokes | Schema 4; 12/12; guards `PASS` |
| 12 | Coverage | API/web >=85 % x4 |
| 13 | Logs/métricas | Logger seguro + observabilidad/reconciliación implementados |
| 14 | Defectos/deuda | 0 Sev1/Sev2 locales; CI/sandbox externos pendientes |
| 15 | Riesgos de integración | Provider real, URLs/firmas y sandbox aislado |
| 16 | Plan UAT | Matriz heredada; ejecución P0/P1 reservada a E6 |
| 17 | Rollback/limpieza | Procesos locales acotados; evidencia/runtime regenerable; sin recursos AWS |
| 18 | `GATE-E5-03` | `FAIL — PENDING_COMMIT_AND_REMOTE_CI` |

Pasos exactos para habilitar etapa 6:

1. crear los commits temáticos autorizados y registrar el SHA de cierre;
2. publicar la rama/PR sin force push;
3. esperar CI verde del SHA y registrar `EVD-E5-29`;
4. confirmar que sandbox sigue siendo la única deuda;
5. cambiar `GATE-E5-03` a `CONDITIONAL_GO`.

Trabajo reservado a etapa 6: integración sandbox autorizada/repetida, UAT P0/P1, cross-browser, accesibilidad completa, Web Vitals, carga seleccionada, DAST/ZAP y hardening desplegado.