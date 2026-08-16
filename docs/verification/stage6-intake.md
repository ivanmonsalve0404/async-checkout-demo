# Etapa 6 — Intake y reconciliación de baseline

## Estado

`STATUS_BY_SAME_SHA_MANIFEST`. Este documento congela identidades y discrepancias de entrada; no convierte resultados heredados en resultados de Etapa 6 ni sustituye al manifiesto runtime del candidato.

## Precedencia aplicada

1. Instrucción vigente de Etapa 6 para proceso, gates y artefactos.
2. `output/etapas-0-1-incepcion-y-requisitos.md` para identidades y denominadores canónicos.
3. `output/etapa-2-diseno-ux-ui.md` para viewports y presupuestos UX.
4. `output/etapa-3-arquitectura-diseno-tecnico.md` y `output/architecture/openapi.yaml` para vocabulario, contratos e invariantes.
5. `output/etapa-4-fundacion-walking-skeleton.md` para toolchain y fundación.
6. `docs/build/slice-plan.md`, `docs/build/test-catalog.json` y `output/etapa-5-construccion-vertical-slices.md` para implementación y pruebas existentes.

Una cifra de la instrucción no reemplaza un registro canónico. No se renumeran IDs ni se crean casos para completar una cifra obsoleta.

## Denominadores reconciliados

| Registro               | Conteo canónico | Fuente verificable             | Observación                                                |
| ---------------------- | --------------: | ------------------------------ | ---------------------------------------------------------- |
| Cláusulas hoja `SRC-*` |             131 | Etapas 0–1 §7 y §26            | 106 MUST, 13 SHOULD, 6 MAY, 6 BONUS                        |
| Requisitos             |              61 | Etapas 0–1 §26                 | 33 RF + 28 RNF                                             |
| Historias              |              12 | Etapas 0–1 §26                 | `US-01..12`                                                |
| Acceptance criteria    |              45 | Etapas 0–1 §26                 | `AC-US-*`; no existen 66 AC canónicos                      |
| Scenario criteria      |              51 | Etapas 0–1 §26                 | `SC-*`                                                     |
| Errores                |              24 | Etapas 0–1 §23/§26 y OpenAPI   | `ERR-01..24`; 21 P0 + 3 P1                                 |
| Datos                  |              72 | Etapas 0–1 §26                 | `DAT-01..72`                                               |
| UAT                    |              48 | Etapas 0–1 §24/§26             | 45 P0 + 3 P1 (`UAT-14/15/16`)                              |
| Slices                 |              13 | Plan E5 §5                     | `SLI-E5-01..13`                                            |
| Conjunto de cierre E5  |             100 | Plan E5 §6.1                   | Etiqueta histórica “P0”; incluye `RF-04`, canónicamente P1 |
| Catálogo ejecutable E5 |              38 | `docs/build/test-catalog.json` | 36 ejecutables + 2 P1 diferidos                            |
| Fake provider          |              12 | E5 §§12/21                     | `FAKE-E5-01..12`                                           |
| Smoke heredado         |              12 | E5 §§21/22                     | `SMK-E5-01..12`                                            |
| API/OpenAPI            |              14 | E3/E5 y OpenAPI                | 14 paths, operaciones, operationIds e IDs API              |

## Anomalías de la instrucción E6

| ID          | Texto recibido                                                | Baseline canónica                                                                                                                             | Tratamiento                                                                                                    |
| ----------- | ------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| `ANM-E6-01` | §3.1 indica 66 AC                                             | 45 AC únicos                                                                                                                                  | Usar 45; no inventar 21 IDs                                                                                    |
| `ANM-E6-02` | §3.1 indica 22 errores                                        | 24 errores (`ERR-01..24`)                                                                                                                     | Usar 24; preservar el OpenAPI y catálogo vigentes                                                              |
| `ANM-E6-03` | §24.1 espera 34 UAT                                           | 48 UAT (`UAT-01..48`)                                                                                                                         | Ejecutar 48; conservar prioridades 45 P0/3 P1                                                                  |
| `ANM-E6-04` | Reporte E5 conserva `GATE-E5-03=FAIL` por falta de commit/CI  | El merge `eaa20ccbb05ab7fdd563009934b25f6c57451311` y cuatro checks remotos exitosos satisfacen esa condición; sandbox sigue sin autorización | Registrar `CHG-E6-01`, no reescribir E5 y reconciliar `GATE-E5-03=CONDITIONAL_GO`                              |
| `ANM-E6-05` | Toolchain fijado en Node 24.19.0                              | Shell de intake observó Node 24.4.1; pnpm 11.19.0 sí coincide                                                                                 | Ejecutar la campaña con Node 24.19.0; el shell observado no es evidencia válida de gate                        |
| `ANM-E6-06` | Plan E5 §6.1 etiqueta `RF-04` como RF P0                      | Etapas 0–1 §11 clasifica 31 RF P0 y 2 RF P1: `RF-04` y `RF-33`                                                                                | No reescribir E5; tratar sus 100 identidades como conjunto histórico y conservar prioridad P1 de `RF-04` en E6 |
| `ANM-E6-07` | UAT-22/UAT-45 heredaron errores HTTP síncronos postaceptación | `CHG-16` y OpenAPI disponen `ERR-12/13=TRANSACTION_200_AFTER_ACCEPTED_SUBMISSION`                                                             | Aplicar `CHG-E6-UAT-22-45`: POST 202; GET Transaction 200; 503 sólo antes de aceptar                           |

## Reconciliación formal de `GATE-E5-03`

| Cambio      | Evidencia remota                                                                                                                                                                                                                      | Resultado                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `CHG-E6-01` | Merge `eaa20ccbb05ab7fdd563009934b25f6c57451311`; CI run `31927027725`: Metadata `95116093466`, Verify `95116110420`, Summary `95116373727`; Security run `31927027745`: Security `95116093523`; los cuatro jobs terminaron `success` | `GATE-E5-03=CONDITIONAL_GO`; integración real continúa bloqueada por `ADR-09`/autorización |

## Identidades fuera o bloqueadas

| Identidad                                        | Disposición vigente              | Efecto en Etapa 6                                                                                  |
| ------------------------------------------------ | -------------------------------- | -------------------------------------------------------------------------------------------------- |
| `RF-33`, `API-11`, `TC-INT-13`, `TC-CONTRACT-04` | `DEFERRED_P1` / `ADR-09 BLOCKED` | Webhook real `NOT_RUN_AUTH_REQUIRED`; no simular verde                                             |
| `UAT-14`                                         | IF/local con fixtures sintéticos | Firma inválida, duplicado y fuera de orden bajo `STATUS_BY_SAME_SHA_MANIFEST`; no requiere sandbox |
| `RNF-10`, `RNF-23`, `UAT-33`                     | Despliegue/HTTPS reservado a E7  | `NOT_RUN_AUTH_REQUIRED` hasta entorno propio autorizado                                            |
| `RNF-28`, `UAT-15`                               | P1 cross-browser                 | Verificar local/CI si los tres motores están disponibles; no heredar PASS                          |
| Sandbox y proveedor real                         | Sin `AUTH-E6-*`                  | Cero tráfico externo, transacciones o dashboard                                                    |
| DAST/headers reales                              | Sin target QA propio autorizado  | `NOT_RUN_AUTH_REQUIRED`; no escanear proveedor ni terceros                                         |

## Regla de cierre

Los reportes E5 son evidencia histórica, no una ejecución E6. El estado efectivo de un ítem lo determina `STATUS_BY_SAME_SHA_MANIFEST` cuando existe evidencia E6 con run ID, SHA, UTC, entorno, comando/procedimiento, resultado, sanitización y checksum aplicable. Las verificaciones externas sin autorización conservan su estado explícito y limitan `GATE-E6-03` según la política del cierre runtime.
