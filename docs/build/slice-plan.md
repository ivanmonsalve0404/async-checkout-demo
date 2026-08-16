# Etapa 5 — Plan de construcción por vertical slices

## 1. Control del plan

| Campo             | Valor                                                         |
| ----------------- | ------------------------------------------------------------- |
| Estado            | `LOCAL_FAKE_VERIFIED`; cierre formal pendiente de snapshot/CI |
| Rama              | `feature/stage-5-vertical-slices`                             |
| Commit base       | `6462d30`                                                     |
| Contrato canónico | `output/architecture/openapi.yaml`                            |
| Modalidad         | Local con fake y DynamoDB Local; cero red externa             |
| Alcance           | Un SKU y una unidad por checkout                              |
| Gate de entrada   | `GATE-E4-03 = PASS`                                           |
| Gate de salida    | `FAIL`; `PENDING_COMMIT_AND_REMOTE_CI`                        |

Este plan conserva las 14 operaciones OpenAPI existentes. No crea rutas auxiliares para quote, reconciliación, selección de fixture o sandbox: esas capacidades se componen dentro de los recursos y puertos ya aprobados.

## 2. Autorizaciones y límites

| ID           | Operación                      | Estado       | Efecto durante etapa 5                           |
| ------------ | ------------------------------ | ------------ | ------------------------------------------------ |
| `AUTH-E5-01` | Llamar endpoints sandbox       | `DENIED`     | Adapter aislado y deshabilitado; cero llamadas   |
| `AUTH-E5-02` | Crear transacción sandbox      | `DENIED`     | Sólo fixtures sintéticos                         |
| `AUTH-E5-03` | Configurar webhook             | `DENIED`     | `API-11` permanece `DEFERRED_P1`                 |
| `AUTH-E5-04` | Entrar al dashboard compartido | `DENIED`     | No se abre ni modifica                           |
| `AUTH-E5-05` | Desplegar a AWS                | `DENIED`     | Sólo ejecución local y synth autorizado heredado |
| `AUTH-E5-06` | Rotar llaves o modificar 2FA   | `PROHIBITED` | No se ejecuta bajo ninguna circunstancia         |

Estado contractual del sandbox: `READY_DISABLED`; smoke externo: `NOT_RUN_AUTH_REQUIRED`.

## 3. Invariantes transversales

1. Precio, moneda, tarifas, stock, quote y estado final son autoridad del servidor.
2. PAN, vencimiento y CVC sólo existen en la frontera efímera de tokenización del navegador; la API propia recibe un token opaco.
3. Reserva, idempotencia y transacción local `PENDING` se persisten antes del primer I/O del proveedor.
4. `APPROVED` consume la reserva (`CONSUMED`) y crea exactamente una entrega.
5. `DECLINED` y `ERROR` liberan la reserva; no consumen stock ni crean entrega.
6. El resultado incierto permanece `paymentStatus=PENDING` con `dispatchPhase=UNKNOWN`; no se inventa el estado `PENDING_RECONCILIATION`.
7. Un estado final nunca regresa a `PENDING` y un replay nunca repite efectos.
8. La misma idempotency key y hash retorna el recurso existente; un hash diferente produce `ERR-10`.
9. El navegador consulta la API propia; `GET /transactions/{transactionId}` no dispara I/O externo.
10. `API-11` no se implementa ni se configura durante esta etapa.

## 4. Registro de cambio controlado

| ID          | Fuente y divergencia                                                                                                                                 | Decisión aplicada                                                                                                       | Impacto                                                                                               | Alternativa descartada                         | Autoridad                                                   |
| ----------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- | ---------------------------------------------- | ----------------------------------------------------------- |
| `CHG-E5-01` | La instrucción E5 usa reserva `COMMITTED` y estado local `PENDING_RECONCILIATION`; E3/OpenAPI congelan `CONSUMED`, `PaymentStatus` y `DispatchPhase` | Conservar `ReservationStatus=CONSUMED`; representar incertidumbre con `paymentStatus=PENDING` + `dispatchPhase=UNKNOWN` | Implementación, fixtures, pruebas, UI y evidencia usan un solo vocabulario; cero rutas/schemas nuevos | Ampliar enums y mantener dos fuentes de verdad | Precedencia contractual aprobada por `CHG-17`; owner `ARCH` |

## 5. Secuencia y resultado demostrable

| Slice       | Capacidad demostrable                                      | Dependencias | Estado de cierre                      |
| ----------- | ---------------------------------------------------------- | ------------ | ------------------------------------- |
| `SLI-E5-01` | Producto y stock canónicos habilitan o bloquean checkout   | Seed E4      | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-02` | Sesión opaca se crea y recupera tras refresh               | 01           | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-03` | Cliente y borrador de entrega se validan y persisten       | 02           | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-04` | Quote COP y breakdown se calculan en servidor              | 01–03        | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-05` | Dos contratos se muestran y aceptan por separado           | 02, 04       | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-06` | Tarjeta sintética se tokeniza sin tocar backend/storage    | 05           | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-07` | PENDING local, reserva e idempotencia preceden al provider | 01–06        | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-08` | Fake determinista reproduce 12 escenarios                  | 07           | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-09` | Adapter sandbox comparte puerto y falla cerrado            | 05–08        | `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED` |
| `SLI-E5-10` | Polling/reconciliación resuelven o conservan incertidumbre | 07–08        | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-11` | Aprobación consume stock y crea una entrega una vez        | 07–10        | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-12` | Declined/error/void/unknown no generan efectos indebidos   | 07–10        | `IMPLEMENTED_VERIFIED`                |
| `SLI-E5-13` | Refresh, resultado y retorno recuperan estado canónico     | 01–12        | `IMPLEMENTED_VERIFIED`                |

Los doce slices locales/fake están `IMPLEMENTED_VERIFIED`. `SLI-E5-09` permanece `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED`: el adapter falla cerrado y su smoke real requiere `AUTH-E5-01/02`, que siguen denegadas.

## 6. Matriz de trazabilidad A — requisito, historia, UX y contrato

| Slice ID    | Requirement ID                                        | User story                         | Acceptance criterion                                               | UX flow/screen                                             | OpenAPI operation/schema                                                                                                                                              |
| ----------- | ----------------------------------------------------- | ---------------------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SLI-E5-01` | `RF-01`, `RF-16`, `RF-25`, `RF-29`                    | `US-01`, `US-11`                   | `AC-US-01-01..03`, `AC-US-11-01..02`                               | `UXF-01/02`; producto loading/available/out-of-stock/error | `listProducts`, `getProduct`, `getProductStock`; `ProductPublic`, `ProductResponse`, `ProductCollectionResponse`, `StockResponse`                                     |
| `SLI-E5-02` | `RF-02`, `RF-13`, `RF-24`, `RF-32`                    | `US-02`, `US-09`                   | `AC-US-02-01..04`, `AC-US-09-01/02/05`                             | `UXF-03/12/13`; modal y boot recovery                      | `createCheckout`, `getCheckout`; `CreateCheckoutRequest`, `CheckoutCreatedResponse`, `CheckoutResponse`                                                               |
| `SLI-E5-03` | `RF-21`, `RF-22`, `RF-27`, `RF-28`, `RF-32`           | `US-03`                            | `AC-US-03-03/04`                                                   | `UXF-05/12`; datos de cliente y entrega                    | `replaceCheckoutCustomer`, `replaceCheckoutDeliveryDetails`; `ReplaceCustomerRequest`, `CustomerResponse`, `ReplaceDeliveryDetailsRequest`, `DeliveryDetailsResponse` |
| `SLI-E5-04` | `RF-06`, `RF-24`                                      | `US-04`                            | `AC-US-04-01..03`                                                  | `UXF-01/06`; resumen, stale y recotización                 | `createCheckout`, `getCheckout`; `Quote`, `CheckoutCreatedResponse`, `CheckoutResponse`                                                                               |
| `SLI-E5-05` | `RF-05`, `RF-17`, `RF-23`                             | `US-03`                            | `AC-US-03-05/06`                                                   | `UXF-04`; dos checkboxes y enlaces                         | `getPaymentConfiguration`, `submitCheckoutTransaction`; `AcceptanceContract`, `PaymentConfigurationResponse`, `PaymentAcceptanceTokens`                               |
| `SLI-E5-06` | `RF-03`, `RF-04`, `RF-18..20`, `RNF-06`               | `US-03`                            | `AC-US-03-01/02`                                                   | `UXF-04/08`; captura aislada y error seguro                | Adapter web; `submitCheckoutTransaction` recibe sólo `PaymentSubmissionRequest.paymentMethodToken`                                                                    |
| `SLI-E5-07` | `RF-07`, `RF-08`, `RF-24`, `RF-29`, `RF-30`, `RF-32`  | `US-05`, `US-10`, `US-11`          | `AC-US-05-01..05`, `AC-US-10-01..04`, `AC-US-11-01..02`            | `UXF-06/07/08/09`; submitting y pending                    | `submitCheckoutTransaction`, `getTransaction`; `PaymentSubmissionRequest`, `PaymentSubmissionResponse`, `TransactionResponse`                                         |
| `SLI-E5-08` | `RF-08`, `RF-09`, `RF-31`                             | `US-05`, `US-06`, `US-07`, `US-08` | `AC-US-05-03..05`, `AC-US-06-01..03`, `AC-US-07-01`, `AC-US-08-01` | `UXF-08..11`; selector sólo test/dev                       | Sin ruta de fixture; puerto usado por `submitCheckoutTransaction` y reconciliador interno                                                                             |
| `SLI-E5-09` | `RF-07..09`, `RF-17`, `RF-23`, `RNF-14`, `RNF-18..20` | `US-03`, `US-05`, `US-06`          | `AC-US-03-01/05`, `AC-US-05-01/05`, `AC-US-06-01..03`              | Misma UX del fake; activación externa bloqueada            | Mismo puerto y schemas de `getPaymentConfiguration`, `submitCheckoutTransaction`, `getTransaction`; sin rutas nuevas                                                  |
| `SLI-E5-10` | `RF-09`, `RF-13`, `RF-26`, `RF-31`, `RF-32`           | `US-06`, `US-09`                   | `AC-US-06-01..03`, `AC-US-09-03/04`                                | `UXF-09/10/11/12`; procesando y seguimos verificando       | `getTransaction`; `PaymentStatus`, `DispatchPhase`, `TransactionResponse`                                                                                             |
| `SLI-E5-11` | `RF-09`, `RF-10`, `RF-11`, `RF-28`, `RF-32`           | `US-07`, `US-11`                   | `AC-US-07-01..03`, `AC-US-11-01..02`                               | `UXF-01/11`; aprobado o conflicto controlado               | `getTransaction`, `getDelivery`; `ReservationStatus`, `IntegrityStatus`, `TransactionResponse`, `DeliveryResponse`                                                    |
| `SLI-E5-12` | `RF-09`, `RF-11`, `RF-13`, `RF-31`                    | `US-08`, `US-09`                   | `AC-US-08-01..04`, `AC-US-09-03/04`                                | `UXF-09/10/11`; fallo final o verificación                 | `getTransaction`; `PaymentStatus`, `DispatchPhase`, `RecoveryCode`, `TransactionResponse`                                                                             |
| `SLI-E5-13` | `RF-12`, `RF-13`, `RF-32`, `RNF-16`, `RNF-17`         | `US-09`, `US-12`                   | `AC-US-09-01..05`, `AC-US-12-01..03`                               | `UXF-01/03/12/13`; cinco pasos, deep link y retorno        | `getCheckout`, `getTransaction`, `getDelivery`, `getProduct`, `getProductStock`; responses canónicos                                                                  |

### 6.1 Matriz atómica P0 de etapa 5

El denominador de cierre es exactamente `100`: `32 RF + 23 RNF + 45 AC`. Cada identidad aparece una sola vez. El snapshot local verifica `99/100`; `RNF-13` queda `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED` hasta que el commit actual se publique y su CI remota quede verde.

| Identidad     | Tipo      | Slice primario          | Prueba/evidencia ejecutable                         | Evidencia            | Estado                                |
| ------------- | --------- | ----------------------- | --------------------------------------------------- | -------------------- | ------------------------------------- |
| `RF-01`       | RF P0     | `SLI-E5-01`             | `TC-INT-01/02`, `TC-E2E-01`, `SMK-E5-01/08`         | `EVD-E5-05/26/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-02`       | RF P0     | `SLI-E5-02`             | `TC-E2E-02`, `SMK-E5-05/10`                         | `EVD-E5-06/24/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-03`       | RF P0     | `SLI-E5-06`             | `TC-UNIT-01`, `TC-CONTRACT-03`                      | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `RF-04`       | RF P0     | `SLI-E5-06`             | `TC-UNIT-01`, `TC-E2E-03`                           | `EVD-E5-10/11`       | `IMPLEMENTED_VERIFIED`                |
| `RF-05`       | RF P0     | `SLI-E5-05`             | `TC-UNIT-09`, `TC-E2E-03`                           | `EVD-E5-09/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-06`       | RF P0     | `SLI-E5-04`             | `TC-UNIT-01`, `TC-INT-03`, `TC-E2E-04`, `SMK-E5-09` | `EVD-E5-08/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-07`       | RF P0     | `SLI-E5-07`             | `TC-INT-04/10`, `TC-E2E-05`, `SMK-E5-07`            | `EVD-E5-12..14/20`   | `IMPLEMENTED_VERIFIED`                |
| `RF-08`       | RF P0     | `SLI-E5-08`             | `TC-CONTRACT-01/02`, `FAKE-E5-01..12`               | `EVD-E5-15..20`      | `IMPLEMENTED_VERIFIED`                |
| `RF-09`       | RF P0     | `SLI-E5-10`             | `TC-UNIT-03`, `TC-INT-08`, `SMK-E5-04/06/11`        | `EVD-E5-18/19/25`    | `IMPLEMENTED_VERIFIED`                |
| `RF-10`       | RF P0     | `SLI-E5-11`             | `TC-INT-05/15/18`, `SMK-E5-01/08/12`                | `EVD-E5-21/26`       | `IMPLEMENTED_VERIFIED`                |
| `RF-11`       | RF P0     | `SLI-E5-12`             | `TC-INT-06/16/17`, `SMK-E5-02/03/11/12`             | `EVD-E5-22/23`       | `IMPLEMENTED_VERIFIED`                |
| `RF-12`       | RF P0     | `SLI-E5-13`             | `TC-E2E-12`, `SMK-E5-01..03`                        | `EVD-E5-26/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-13`       | RF P0     | `SLI-E5-13`             | `TC-E2E-09/12`, `SMK-E5-05/06/10`                   | `EVD-E5-24..26`      | `IMPLEMENTED_VERIFIED`                |
| `RF-14`       | RF P0     | `SLI-E5-01/03/07/10/11` | `TC-INT-01/12`, `TC-CONTRACT-05`                    | `EVD-E5-03/04/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-15`       | RF P0     | `SLI-E5-01..13`         | `TC-INT-12`, `TC-CONTRACT-05`                       | `EVD-E5-03/04/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-16`       | RF P0     | `SLI-E5-01`             | `TC-INT-02`                                         | `EVD-E5-05/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-17`       | RF P0     | `SLI-E5-05`             | `TC-UNIT-09`, `TC-E2E-03`                           | `EVD-E5-09/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-18`       | RF P0     | `SLI-E5-06`             | `TC-UNIT-01`, `TC-CONTRACT-03`                      | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `RF-19`       | RF P0     | `SLI-E5-06`             | `TC-UNIT-01`, `TC-E2E-03`                           | `EVD-E5-10/11`       | `IMPLEMENTED_VERIFIED`                |
| `RF-20`       | RF P0     | `SLI-E5-06`             | `TC-UNIT-01`, `TC-CONTRACT-03`                      | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `RF-21`       | RF P0     | `SLI-E5-03`             | `TC-INT-03`, `TC-E2E-03`, `SMK-E5-05`               | `EVD-E5-07/24/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-22`       | RF P0     | `SLI-E5-03`             | `TC-INT-03`, `TC-E2E-03`, `SMK-E5-05`               | `EVD-E5-07/24/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-23`       | RF P0     | `SLI-E5-05`             | `TC-UNIT-09`, `TC-CONTRACT-01`, `TC-E2E-03`         | `EVD-E5-09/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-24`       | RF P0     | `SLI-E5-04`             | `TC-UNIT-01`, `TC-INT-03`, `SMK-E5-09`              | `EVD-E5-08/31`       | `IMPLEMENTED_VERIFIED`                |
| `RF-25`       | RF P0     | `SLI-E5-01`             | `TC-INT-01/02`, `SMK-E5-01/08`                      | `EVD-E5-05/26/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-26`       | RF P0     | `SLI-E5-10`             | `TC-INT-08/12`, `SMK-E5-04/06`                      | `EVD-E5-18/19/25/31` | `IMPLEMENTED_VERIFIED`                |
| `RF-27`       | RF P0     | `SLI-E5-03`             | `TC-INT-03/11`, `TC-E2E-03`                         | `EVD-E5-07/24/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-28`       | RF P0     | `SLI-E5-11`             | `TC-INT-11/18`, `SMK-E5-01/12`                      | `EVD-E5-21/23/31`    | `IMPLEMENTED_VERIFIED`                |
| `RF-29`       | RF P0     | `SLI-E5-07`             | `TC-INT-05/09/10`, `SMK-E5-07/08`                   | `EVD-E5-12/20/21`    | `IMPLEMENTED_VERIFIED`                |
| `RF-30`       | RF P0     | `SLI-E5-07`             | `TC-UNIT-04`, `TC-INT-10`, `SMK-E5-07/12`           | `EVD-E5-13/14/20`    | `IMPLEMENTED_VERIFIED`                |
| `RF-31`       | RF P0     | `SLI-E5-10`             | `TC-INT-08`, `TC-E2E-06`, `SMK-E5-04/06/11`         | `EVD-E5-18/19/25`    | `IMPLEMENTED_VERIFIED`                |
| `RF-32`       | RF P0     | `SLI-E5-02`             | `TC-INT-11`, `TC-E2E-09`, `SMK-E5-05/06/10`         | `EVD-E5-06/24/25/31` | `IMPLEMENTED_VERIFIED`                |
| `RNF-01`      | RNF P0 E5 | `SLI-E5-13`             | Build e inspección SPA                              | `EVD-E5-27/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-02`      | RNF P0 E5 | `SLI-E5-13`             | Jest store/Redux y flujo E2E                        | `EVD-E5-24/25/27/31` | `IMPLEMENTED_VERIFIED`                |
| `RNF-03`      | RNF P0 E5 | `SLI-E5-13`             | `SMK-E5-01..12` en viewport móvil                   | `EVD-E5-26/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-04`      | RNF P0 E5 | `SLI-E5-01..12`         | Typecheck, boundaries y tests API                   | `EVD-E5-27/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-05`      | RNF P0 E5 | `SLI-E5-01..12`         | Boundaries y tests de controllers/use cases         | `EVD-E5-27/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-06`      | RNF P0 E5 | `SLI-E5-06`             | `TC-CONTRACT-03`, storage allowlist y secret scan   | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-07`      | RNF P0 E5 | `SLI-E5-13`             | `TC-E2E-09`, `SMK-E5-05/06/10`                      | `EVD-E5-24..26`      | `IMPLEMENTED_VERIFIED`                |
| `RNF-08`      | RNF P0 E5 | `SLI-E5-01..13`         | Jest web/API                                        | `EVD-E5-27`          | `IMPLEMENTED_VERIFIED`                |
| `RNF-09`      | RNF P0 E5 | `SLI-E5-01..13`         | Coverage web/API en cuatro métricas                 | `EVD-E5-27`          | `IMPLEMENTED_VERIFIED`                |
| `RNF-11`      | RNF P0 E5 | `SLI-E5-01..13`         | `openapi:lint`, `contracts:check`, `TC-CONTRACT-05` | `EVD-E5-03/04/31`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-12`      | RNF P0 E5 | `SLI-E5-13`             | Inspección README/handoff                           | `EVD-E5-02/31/32`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-13`      | RNF P0 E5 | `SLI-E5-01..13`         | Historial incremental y secret scan `--history`     | `EVD-E5-28/29/31`    | `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED` |
| `RNF-14`      | RNF P0 E5 | `SLI-E5-09`             | Config guard y contract tests sin red               | `EVD-E5-28/30`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-15`      | RNF P0 E5 | `SLI-E5-01/13`          | Component tests y smokes mobile-first               | `EVD-E5-05/26/31`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-16`      | RNF P0 E5 | `SLI-E5-13`             | CSS responsive y `SMK-E5-01..12`                    | `EVD-E5-26/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-17`      | RNF P0 E5 | `SLI-E5-13`             | Jest-axe, foco, trap, Escape y restore              | `EVD-E5-26/31`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-18`      | RNF P0 E5 | `SLI-E5-06`             | `TC-CONTRACT-03`, storage/log allowlists            | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-19`      | RNF P0 E5 | `SLI-E5-03`             | DTO/capability/TTL y redacción PII                  | `EVD-E5-07/28/31`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-20`      | RNF P0 E5 | `SLI-E5-09`             | Config fail-closed y secret scan                    | `EVD-E5-28/30`       | `IMPLEMENTED_VERIFIED`                |
| `RNF-21`      | RNF P0 E5 | `SLI-E5-01..13`         | Jest frontend                                       | `EVD-E5-27`          | `IMPLEMENTED_VERIFIED`                |
| `RNF-22`      | RNF P0 E5 | `SLI-E5-01..12`         | Jest backend                                        | `EVD-E5-27`          | `IMPLEMENTED_VERIFIED`                |
| `RNF-26`      | RNF P0 E5 | `SLI-E5-02/07/10`       | `TC-INT-11/12`, middleware y API contract           | `EVD-E5-10/28/31`    | `IMPLEMENTED_VERIFIED`                |
| `RNF-27`      | RNF P0 E5 | `SLI-E5-07/10/12`       | Safe logger, correlation y redaction tests          | `EVD-E5-28/32`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-01-01` | AC P0     | `SLI-E5-01`             | `TC-INT-01/02`, `TC-E2E-01`                         | `EVD-E5-05/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-01-02` | AC P0     | `SLI-E5-01`             | `TC-E2E-01`, `SMK-E5-08`                            | `EVD-E5-05/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-01-03` | AC P0     | `SLI-E5-01`             | `TC-INT-02`, product component test                 | `EVD-E5-05/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-02-01` | AC P0     | `SLI-E5-02`             | `TC-E2E-02`                                         | `EVD-E5-06/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-02-02` | AC P0     | `SLI-E5-02`             | Modal focus/close component test                    | `EVD-E5-06/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-02-03` | AC P0     | `SLI-E5-02`             | Checkout creation/recovery test                     | `EVD-E5-06/24`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-02-04` | AC P0     | `SLI-E5-02`             | Error/expiry recovery test, `SMK-E5-10`             | `EVD-E5-06/24`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-01` | AC P0     | `SLI-E5-06`             | `TC-CONTRACT-03`, negative backend payload test     | `EVD-E5-10/11/28`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-02` | AC P0     | `SLI-E5-06`             | `TC-UNIT-01`, card component tests                  | `EVD-E5-10/11`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-03` | AC P0     | `SLI-E5-03`             | `TC-INT-03`, customer component test                | `EVD-E5-07/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-04` | AC P0     | `SLI-E5-03`             | `TC-INT-03`, `SMK-E5-05`                            | `EVD-E5-07/24`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-05` | AC P0     | `SLI-E5-05`             | `TC-UNIT-09`, acceptance component test             | `EVD-E5-09/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-03-06` | AC P0     | `SLI-E5-05`             | `TC-E2E-03`, review component test                  | `EVD-E5-09/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-04-01` | AC P0     | `SLI-E5-04`             | `TC-UNIT-01`, `TC-INT-03`                           | `EVD-E5-08/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-04-02` | AC P0     | `SLI-E5-04`             | `TC-INT-03`, manipulated payload test               | `EVD-E5-08/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-04-03` | AC P0     | `SLI-E5-04`             | `TC-INT-03`, `SMK-E5-09`                            | `EVD-E5-08/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-05-01` | AC P0     | `SLI-E5-07`             | `TC-INT-04`                                         | `EVD-E5-12/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-05-02` | AC P0     | `SLI-E5-07`             | `TC-INT-04`, API contract test                      | `EVD-E5-12/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-05-03` | AC P0     | `SLI-E5-07`             | `TC-INT-10`, `SMK-E5-07`                            | `EVD-E5-13/20`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-05-04` | AC P0     | `SLI-E5-12`             | `TC-INT-07`, fake not-sent test                     | `EVD-E5-17/22/23`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-05-05` | AC P0     | `SLI-E5-12`             | `TC-INT-07/08`, unknown/replay tests                | `EVD-E5-19/20`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-06-01` | AC P0     | `SLI-E5-10`             | `TC-INT-08`, `SMK-E5-04/06`                         | `EVD-E5-18/19/25`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-06-02` | AC P0     | `SLI-E5-10`             | `TC-INT-08`, fake terminal transitions              | `EVD-E5-18/21/22`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-06-03` | AC P0     | `SLI-E5-10`             | `TC-INT-08`, prolonged pending test                 | `EVD-E5-19/25`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-07-01` | AC P0     | `SLI-E5-11`             | `TC-INT-05`, `SMK-E5-01/08`                         | `EVD-E5-21/26`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-07-02` | AC P0     | `SLI-E5-11`             | `TC-INT-18`, `SMK-E5-12`                            | `EVD-E5-21/26`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-07-03` | AC P0     | `SLI-E5-11`             | `TC-INT-15`, inventory conflict test                | `EVD-E5-21/32`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-08-01` | AC P0     | `SLI-E5-12`             | `TC-INT-06`, `SMK-E5-02/03`                         | `EVD-E5-22/23`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-08-02` | AC P0     | `SLI-E5-12`             | `TC-INT-16`, VOIDED active test                     | `EVD-E5-22/23`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-08-03` | AC P0     | `SLI-E5-12`             | `TC-INT-16`, post-consumption conflict test         | `EVD-E5-22/23/32`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-08-04` | AC P0     | `SLI-E5-12`             | `TC-INT-17`, final conflict test                    | `EVD-E5-20/23/32`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-09-01` | AC P0     | `SLI-E5-13`             | `TC-E2E-09`, `SMK-E5-05`                            | `EVD-E5-24`          | `IMPLEMENTED_VERIFIED`                |
| `AC-US-09-02` | AC P0     | `SLI-E5-13`             | `TC-E2E-09`, storage allowlist test                 | `EVD-E5-24/28`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-09-03` | AC P0     | `SLI-E5-13`             | `TC-INT-08`, `SMK-E5-06`                            | `EVD-E5-25`          | `IMPLEMENTED_VERIFIED`                |
| `AC-US-09-04` | AC P0     | `SLI-E5-13`             | `TC-E2E-09`, final replay test                      | `EVD-E5-25/26`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-09-05` | AC P0     | `SLI-E5-13`             | `TC-INT-11`, `SMK-E5-10`                            | `EVD-E5-24/28`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-10-01` | AC P0     | `SLI-E5-07`             | `TC-INT-10`, `SMK-E5-07/12`                         | `EVD-E5-13/20`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-10-02` | AC P0     | `SLI-E5-07`             | `TC-UNIT-04`, `TC-INT-10`                           | `EVD-E5-14/20`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-10-03` | AC P0     | `SLI-E5-07`             | `TC-INT-10`, active-payment conflict test           | `EVD-E5-13/14/20`    | `IMPLEMENTED_VERIFIED`                |
| `AC-US-10-04` | AC P0     | `SLI-E5-07`             | `TC-E2E-10`, replay tests                           | `EVD-E5-13/20`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-11-01` | AC P0     | `SLI-E5-07`             | `TC-INT-09`, `SMK-E5-08`                            | `EVD-E5-20/21`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-11-02` | AC P0     | `SLI-E5-07`             | `TC-INT-09`, `SMK-E5-08`                            | `EVD-E5-20/21`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-12-01` | AC P0     | `SLI-E5-13`             | `TC-E2E-12`, transaction component tests            | `EVD-E5-26/31`       | `IMPLEMENTED_VERIFIED`                |
| `AC-US-12-02` | AC P0     | `SLI-E5-13`             | `TC-E2E-12`, `SMK-E5-01`                            | `EVD-E5-26`          | `IMPLEMENTED_VERIFIED`                |
| `AC-US-12-03` | AC P0     | `SLI-E5-13`             | `TC-E2E-12`, retry/new-attempt test                 | `EVD-E5-22/26`       | `IMPLEMENTED_VERIFIED`                |

Identidades deliberadamente fuera del denominador P0 de etapa 5:

| Identidad | Prioridad | Disposición                                                                | Slice/no-regresión          | Prueba/evidencia                           |
| --------- | --------- | -------------------------------------------------------------------------- | --------------------------- | ------------------------------------------ |
| `RF-33`   | P1        | `DEFERRED_P1`; webhook opcional reservado hasta aislamiento y autorización | `SLI-E5-09`; `API-11`       | `TC-INT-13`, `TC-CONTRACT-04`; `EVD-E5-30` |
| `RNF-10`  | P0 global | Fuera de alcance E5; publicación corresponde a etapa 7                     | Sin slice E5                | Gate de release E7                         |
| `RNF-23`  | P0 global | Fuera de alcance E5; AWS/HTTPS corresponde a etapa 7                       | Sin slice E5                | Smoke/TLS E7                               |
| `RNF-24`  | P0 global | Verificación final reservada a etapa 6                                     | No-regresión `SLI-E5-01/13` | Component tests y `SMK-E5-01..12`          |
| `RNF-25`  | P0 global | Verificación final reservada a etapa 6                                     | No-regresión `SLI-E5-01/13` | Build e inspección del asset               |
| `RNF-28`  | P1        | `DEFERRED_P1`; cross-browser ampliado corresponde a etapa 6                | No-regresión `SLI-E5-13`    | Smoke local; matriz cross-browser E6       |

## 7. Matriz de trazabilidad B — implementación, datos, pruebas y evidencia

| Slice ID    | Use case                                                               | Domain invariant                                                    | Data entity/field                                              | Error IDs                        | Test IDs                                                 | Evidence IDs       | PR/commit                     | Status                                                          |
| ----------- | ---------------------------------------------------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------- | ------------------ | ----------------------------- | --------------------------------------------------------------- |
| `SLI-E5-01` | `ListProducts`, `GetProduct`, `GetProductAvailability`                 | Disponible nunca negativo; producto server-authoritative            | `Product`, `Inventory.available`                               | `ERR-04/06/19/20`                | `TC-INT-01/02`, `TC-E2E-01`, `SMK-E5-01/08`              | `EVD-E5-05/26/31`  | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-02` | `CreateCheckoutSession`, `GetCheckoutSession`, `ExpireCheckoutSession` | Capability opaca; versión monotónica; refresh no duplica            | `CheckoutSession.id/status/version/expiresAt`                  | `ERR-02/03/04/05/06/08/09`       | `TC-E2E-02/09`, `TC-INT-11`, `SMK-E5-05/10`              | `EVD-E5-06/24/31`  | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-03` | `UpdateCustomerAndDeliveryDraft`                                       | Entrega confirmada aún no existe; PII redactada                     | `Customer`; `CheckoutSession.customer/deliveryDraft`           | `ERR-01/02/03/05/08/09`          | `TC-INT-03`, `TC-E2E-03`, `SMK-E5-05`                    | `EVD-E5-07/24/31`  | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-04` | `CreateQuote`                                                          | Enteros COP; total = subtotal + base + envío; cliente no fija monto | `Quote.id/amounts/version/expiresAt`                           | `ERR-04/06/07/08/09`             | `TC-UNIT-01`, `TC-INT-03`, `TC-E2E-04`, `SMK-E5-09`      | `EVD-E5-08/31`     | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-05` | `GetPaymentConfiguration`, `ValidatePaymentAcceptances`                | Dos aceptaciones independientes y vigentes                          | `AcceptanceContract`; evidencia permitida `acceptedAt/version` | `ERR-05/09/23/24`                | `TC-UNIT-09`, `TC-CONTRACT-01`, `TC-E2E-03`              | `EVD-E5-09/31`     | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-06` | `TokenizeCard` en adapter web                                          | C4 nunca llega a API/storage/logs; token se descarta                | C4 efímero; `paymentMethodToken` C3 en tránsito                | `ERR-05/12/23/24`                | `TC-UNIT-01`, `TC-CONTRACT-03`, `UAT-29/45/48`           | `EVD-E5-10/11/28`  | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-07` | `StartPayment`                                                         | Local PENDING primero; key+hash estable; una reserva activa         | `Transaction`, `InventoryReservation`, `IdempotencyRecord`     | `ERR-06/07/08/09/10/11/12/13/14` | `TC-INT-04/07/10`, `TC-E2E-05/10/11`, `SMK-E5-07/08`     | `EVD-E5-12..14/20` | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-08` | `FakePaymentGatewayAdapter.create/get`                                 | 12 escenarios deterministas; cero red externa                       | Fixtures sintéticos y reloj inyectado                          | `ERR-12/13/14/18/21/22/24`       | `FAKE-E5-01..12`, `SMK-E5-01..04/11/12`                  | `EVD-E5-15..20`    | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-09` | `SandboxPaymentGatewayAdapter`, `SandboxMerchantContractAdapter`       | Fail closed; no retry ciego; mismo puerto que fake                  | Config sólo por entorno; cero secretos versionados             | `ERR-12/13/14/23/24`             | Fixtures contractuales; smoke no ejecutado               | `EVD-E5-30`        | Snapshot local; SHA pendiente | `IMPLEMENTED_NOT_EXTERNALLY_VERIFIED`; adapter `READY_DISABLED` |
| `SLI-E5-10` | `GetTransactionStatus`, `ReconcileTransaction`                         | Final monotónico; dedupe; backoff acotado                           | `Transaction.nextCheckAt/attempts/dispatchPhase`               | `ERR-14/18/19/20/21/22`          | `TC-INT-08`, `TC-E2E-06/09`, `SMK-E5-04/06`              | `EVD-E5-18/19/25`  | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-11` | `FinalizeApprovedTransaction`, `GetDelivery`                           | `APPROVED+ACTIVE -> CONSUMED+stock-1+delivery` atómico una vez      | `Transaction`, `Inventory`, `InventoryReservation`, `Delivery` | `ERR-18/21/22`                   | `TC-INT-05/09/15/18`, `TC-E2E-07/11`, `SMK-E5-01/08/12`  | `EVD-E5-21/26`     | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-12` | `FinalizeFailedTransaction`                                            | Failure libera una vez; unknown conserva; entrega=0                 | `Transaction`, `InventoryReservation`; ausencia `Delivery`     | `ERR-12/13/14/18/21`             | `TC-INT-06/08/16/17`, `TC-E2E-08`, `SMK-E5-02..04/11/12` | `EVD-E5-22/23`     | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |
| `SLI-E5-13` | `RecoverCheckout`, `RecoverTransaction`, `ReturnToProduct`             | Servidor canónico; storage allowlist; cero nuevo POST al recuperar  | IDs opacos locales; checkout/transaction/delivery server-side  | `ERR-03/04/08/14/20/22`          | `TC-E2E-09/12`, `SMK-E5-05/06/10`                        | `EVD-E5-24..26`    | Snapshot local; SHA pendiente | `IMPLEMENTED_VERIFIED`                                          |

## 8. Pruebas y evidencias de cierre

- `FAKE-E5-01..12` y `SMK-E5-01..12`: `12/12 PASS`; smoke schema `4`, guards de red `PASS`, navegador externo `0`, provider `NOT_RUN_AUTH_REQUIRED`, script SHA-256 `1981f13fc5387f73c44994a15949b4c9a49dd3a05cb2396d269397d74cf4009f`.
- API: `28/28` suites y `338/338` tests; coverage statements `92.80 %`, branches `85.81 %`, functions `99.10 %`, lines `94.60 %`.
- Web: `22/22` suites y `98/98` tests; coverage statements `94.35 %`, branches `90.23 %`, functions `88.08 %`, lines `93.99 %`.
- DynamoDB Local real: `1/1` suite y `10/10` tests sobre `amazon/dynamodb-local:2.6.1`, sólo loopback y cero AWS externo.
- OpenAPI/tipos: `14/14` operaciones, `251` refs locales, cero drift; hash LF `aa90d17de283d720ab92112cda8a75ae0663a881cd25da931f56c1148ae4c01a`.
- Trazabilidad ejecutable: `38/38` entradas (`36` ejecutables y `2` P1 diferidas) con selectores resolubles.
- Secret scan de árbol e historial: `PASS`, cero hallazgos; dependencias productivas: cero high/critical.
- `verification-manifest.json` enlaza el snapshot de fuentes, las métricas y estas evidencias sin incluir payloads de prueba.
- `EVD-E5-29` permanece `PENDING_COMMIT_AND_REMOTE_CI`; el SHA exacto sólo puede existir tras un commit autorizado.

## 9. Definition of Done por slice

- Requisito, AC, UX y operación/schema permanecen trazados.
- Caso de uso devuelve `Result` y el controller sólo adapta HTTP.
- Persistencia usa condición/transacción cuando existe concurrencia.
- UI cubre loading, error y estados de negocio aplicables.
- Pruebas positivas, negativas y de ausencia de efectos quedan verdes.
- Evidencia es reproducible, sintética y no contiene C3/C4/PII real.
- No existe deriva OpenAPI/tipos ni ruta paralela.
