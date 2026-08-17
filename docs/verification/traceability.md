# Etapa 6 — Trazabilidad requisito, prueba y evidencia

<!-- stage6-status-authority: ART-VER-03 SAME_SHA_RUNTIME_MANIFEST -->

## Control y denominadores

| Campo      | Valor                                                                                 |
| ---------- | ------------------------------------------------------------------------------------- |
| Artefacto  | `ART-VER-03`                                                                          |
| Estado     | `COMPLETE_BY_SAME_SHA_MANIFEST`                                                       |
| Requisitos | 33 RF + 28 RNF                                                                        |
| AC/SC      | 45 AC + 51 SC                                                                         |
| UAT        | 48 (45 P0, 3 P1)                                                                      |
| Errores    | 24 (`ERR-01..24`)                                                                     |
| Cierre E5  | 100 identidades: 32 RF + 23 RNF + 45 AC; conjunto histórico, no población P0 canónica |

El conjunto histórico de implementación permanece en [slice-plan §6.1](../build/slice-plan.md#61-matriz-atómica-p0-de-etapa-5); este documento lo extiende a verificación E6 sin duplicar ni cambiar identidades, pero conserva la prioridad canónica P1 de `RF-04`. El catálogo [test-catalog.json](../build/test-catalog.json) es la fuente mecánica de runner, archivo y patrón para 38 tests (`36 EXECUTABLE`, `2 DEFERRED_P1`). Un vínculo nominal no basta: el check de trazabilidad debe resolver archivo y patrón antes de ejecutar el runner.

## Conjuntos canónicos

| Conjunto          | Identidades exactas                                                                                                                                              | Disposición E6                                                                                        |
| ----------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| RF P0 construidos | `RF-01..03`, `RF-05..32`                                                                                                                                         | 31 identidades; verificación local/fake obligatoria                                                   |
| RF P1 local       | `RF-04`                                                                                                                                                          | Detección de marca implementada; conserva prioridad canónica P1                                       |
| RF P1 externo     | `RF-33`                                                                                                                                                          | Webhook real `BLOCKED_AUTH`; `TC-INT-13/TC-CONTRACT-04`; `UAT-14` local=`STATUS_BY_SAME_SHA_MANIFEST` |
| RNF P0 E5         | `RNF-01..09`, `RNF-11..22`, `RNF-26/27`                                                                                                                          | 23 identidades; verificación E6                                                                       |
| RNF global E6     | `RNF-24/25`                                                                                                                                                      | Performance/asset obligatorios                                                                        |
| RNF global E7     | `RNF-10/23`                                                                                                                                                      | Cloud/HTTPS `NOT_RUN_AUTH_REQUIRED`                                                                   |
| RNF P1 E6         | `RNF-28`                                                                                                                                                         | Cross-browser ampliado                                                                                |
| AC                | `AC-US-01-01..03`, `02-01..04`, `03-01..06`, `04-01..03`, `05-01..05`, `06-01..03`, `07-01..03`, `08-01..04`, `09-01..05`, `10-01..04`, `11-01..02`, `12-01..03` | 45/45; conservar IDs                                                                                  |

## Cadena por slice

Cada fila representa `Fuente E0 → requisito/AC → slice E5 → test resoluble → UAT → evidencia E6 → gate`. El estado sólo pasa a `VERIFIED` cuando la evidencia E6 se produce sobre el SHA final.

| Slice       | Requisitos / AC                                                     | Tests existentes                                             | UAT                      | Evidencia E6            | Gate        | Estado                          |
| ----------- | ------------------------------------------------------------------- | ------------------------------------------------------------ | ------------------------ | ----------------------- | ----------- | ------------------------------- |
| `SLI-E5-01` | RF-01/16/25/29; AC-US-01-01..03; AC-US-11-01/02                     | `TC-INT-01/02`, `TC-E2E-01`, `SMK-E5-01/08`                  | 06/10/18/37/38           | `EVD-E6-11/14/19/36`    | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-02` | RF-02/13/24/32; AC-US-02-01..04; AC-US-09-01/02/05                  | `TC-E2E-02/09`, `TC-INT-11`, `SMK-E5-05/10`                  | 09/17/25..28/36          | `EVD-E6-14/21/23/34/36` | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-03` | RF-21/22/27/28/32; AC-US-03-03/04                                   | `TC-INT-03/11`, `TC-E2E-03`, `SMK-E5-05`                     | 17/19/44                 | `EVD-E6-12/14/34/35/36` | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-04` | RF-06/24; AC-US-04-01..03                                           | `TC-UNIT-01`, `TC-INT-03`, `TC-E2E-04`, `SMK-E5-09`          | 07/21/39                 | `EVD-E6-10/14/20/36`    | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-05` | RF-05/17/23; AC-US-03-05/06                                         | `TC-UNIT-09`, `TC-CONTRACT-01`, `TC-E2E-03`                  | 19/20                    | `EVD-E6-10/12/36`       | E6-01/03    | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-06` | RF-03/04/18..20; RNF-06; AC-US-03-01/02                             | `TC-UNIT-01`, `TC-CONTRACT-03`; backend negative tests       | 11/13/29/45/48           | `EVD-E6-10/12/31/35/36` | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-07` | RF-07/08/24/29/30/32; AC-US-05-01..05, 10-01..04, 11-01/02          | `TC-INT-04/07/10`, `TC-E2E-05/10/11`, `SMK-E5-07/08`         | 04/05/08/22..24/45/48    | `EVD-E6-14/17..20/36`   | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-08` | RF-08/09/31; AC-US-05-03..05, 06-01..03, 07-01, 08-01               | `TC-CONTRACT-01/02`, `FAKE-E5-01..12`, `SMK-E5-01..04/11/12` | 01..03/08/22/23/40/45/48 | `EVD-E6-12/13/14/16/17` | E6-01/02    | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-09` | RF-07..09/17/23; RNF-14/18..20; AC-US-03-01/05, 05-01/05, 06-01..03 | Adapter sandbox specs; `TC-INT-13/TC-CONTRACT-04` diferidos  | 14/32/48                 | `EVD-E6-12/24/31/35/36` | E6-02/03    | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-10` | RF-09/13/26/31/32; AC-US-06-01..03, 09-03/04                        | `TC-INT-08`, `TC-E2E-06/09`, `SMK-E5-04/06`                  | 03/23/27/34              | `EVD-E6-14/17/21/22/36` | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-11` | RF-09/10/11/28/32; AC-US-07-01..03, 11-01/02                        | `TC-INT-05/09/15/18`, `TC-E2E-07/11`, `SMK-E5-01/08/12`      | 01/06/31/35/43           | `EVD-E6-11/15/18/19/36` | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-12` | RF-09/11/13/31; AC-US-08-01..04, 09-03/04                           | `TC-INT-06/08/16/17`, `TC-E2E-08`, `SMK-E5-02..04/11/12`     | 02/08/22/23/34/40..42    | `EVD-E6-16/17/36`       | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |
| `SLI-E5-13` | RF-12/13/32; RNF-16/17; AC-US-09-01..05, 12-01..03                  | `TC-E2E-09/12`, component specs, `SMK-E5-05/06/10`           | 09/12/15/16/25..28/31/36 | `EVD-E6-14/21..29/36`   | E6-01/02/03 | `COMPLETE_BY_SAME_SHA_MANIFEST` |

## NFR, seguridad y rúbrica

| Identidades                   | Riesgo/control                                     | Test o procedimiento                                    | UAT               | Evidencia              | Estado                                                |
| ----------------------------- | -------------------------------------------------- | ------------------------------------------------------- | ----------------- | ---------------------- | ----------------------------------------------------- |
| RNF-01..05/08/09/11..13/21/22 | Build, arquitectura, documentación, CI y cobertura | `pnpm verify`, configs Jest, fresh clone                | N/A               | `EVD-E6-01..10/38..40` | `STATUS_BY_SAME_SHA_MANIFEST`                         |
| RNF-06/07/18..20/26/27        | Sesión, privacidad, boundary HTTP, logs            | `TC-INT-11`, seguridad/repositorio, pruebas HTTP/logger | 13/17/29/32/46/47 | `EVD-E6-31..35/36`     | `STATUS_BY_SAME_SHA_MANIFEST`; DAST externo bloqueado |
| RNF-14                        | Sandbox fail-closed                                | Specs sandbox + smoke autorizado                        | 32/48             | `EVD-E6-24/34/36`      | Local `PENDING`; externo `NOT_RUN_AUTH_REQUIRED`      |
| RNF-15/16/24/25               | Responsive, asset y performance                    | Matriz siete viewports + lab                            | 12                | `EVD-E6-26/29/30/36`   | `STATUS_BY_SAME_SHA_MANIFEST`                         |
| RNF-17                        | A11y básica                                        | axe + teclado/foco/lectura manual                       | 16/36             | `EVD-E6-27/28/36`      | `STATUS_BY_SAME_SHA_MANIFEST`                         |
| RNF-28                        | Tres motores                                       | Cross-browser real local/CI                             | 15                | `EVD-E6-25/36`         | `STATUS_BY_SAME_SHA_MANIFEST`                         |
| RNF-10/23                     | Deploy/HTTPS                                       | Etapa 7, entorno cloud autorizado                       | 33                | `EVD-E6-36/40`         | `NOT_RUN_AUTH_REQUIRED`                               |

## Cobertura del catálogo de errores

| Errores           | Tests existentes                                   | UAT            | Evidencia E6         | Estado                                                            |
| ----------------- | -------------------------------------------------- | -------------- | -------------------- | ----------------------------------------------------------------- |
| `ERR-01/05/09`    | Unit/component/API DTO, `TC-INT-03`                | 20/30/44/47    | `EVD-E6-10/12/36`    | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-02/03`       | `TC-INT-11/12`, middleware HTTP                    | 17/28          | `EVD-E6-12/34/36`    | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-04/06/07/08` | `TC-INT-02/03/09`                                  | 10/28/37..39   | `EVD-E6-11/19/20/36` | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-10/11`       | `TC-UNIT-04`, `TC-INT-10`, `TC-E2E-10`             | 04/05/24       | `EVD-E6-18/36`       | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-12`          | `TC-INT-07`, `TC-CONTRACT-01`                      | 45             | `EVD-E6-12/16/36`    | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-13/14`       | `TC-INT-07/08`, `TC-CONTRACT-02`                   | 03/08/22/23/34 | `EVD-E6-17/36`       | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-15..17`      | Fixtures locales UAT-14; integración real diferida | 14             | `EVD-E6-12/36`       | Local `STATUS_BY_SAME_SHA_MANIFEST`; real `NOT_RUN_AUTH_REQUIRED` |
| `ERR-18/21`       | `TC-UNIT-03`, `TC-INT-16/17`                       | 40..42         | `EVD-E6-16/36`       | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-19`          | Rate-limit specs/load                              | 46             | `EVD-E6-30/34/36`    | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-20`          | Safe problem/filter specs                          | 47             | `EVD-E6-34/36`       | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-22`          | `TC-INT-15`                                        | 35             | `EVD-E6-15/36`       | `STATUS_BY_SAME_SHA_MANIFEST`                                     |
| `ERR-23/24`       | Config/runtime-security + sandbox contract specs   | 32/48          | `EVD-E6-24/34/36`    | Local `PENDING`; externo `NOT_RUN_AUTH_REQUIRED`                  |

## Criterio mecánico de completitud

La trazabilidad está completa sólo si todos estos controles pasan sobre el mismo SHA:

1. Las 100 identidades de `slice-plan.md` aparecen exactamente una vez y conservan su ID.
2. Los 38 registros de `test-catalog.json` resuelven runner; los 36 ejecutables resuelven archivo y patrón; los dos diferidos conservan razón y autoridad.
3. `UAT-01..48` aparecen exactamente una vez en `uat-results.md`, con prioridad 45 P0/3 P1.
4. `ERR-01..24`, `EVD-E6-01..40` y `ART-VER-01..18` no tienen huecos ni IDs nuevos.
5. Ningún estado distinto de `PASS` se suma como `PASS`; la autoridad de cada fila proviene del manifiesto del mismo SHA.
6. Cada `FAILED` enlaza `DEF-E6-*`; cada fix enlaza commit y regresión.

El estado versionado es `COMPLETE_BY_SAME_SHA_MANIFEST`; la completitud efectiva sólo existe cuando la confirma el manifiesto runtime del mismo SHA.
