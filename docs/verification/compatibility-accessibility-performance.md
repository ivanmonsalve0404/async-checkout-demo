# Etapa 6 — Protocolo de compatibilidad, accesibilidad y rendimiento

<!-- STAGE6_FINAL_AUTHORITY:verification-manifest.json -->

## Autoridad

Este documento define el procedimiento y los inventarios mínimos; no contiene un snapshot de ejecución. El estado, el `runId`, el SHA candidato, los checksums y las métricas promovidas se resuelven exclusivamente desde `output/evidence/stage-6/verification-manifest.json`:

- `RUN_ID_BY_SAME_SHA_MANIFEST`
- `SHA_BY_SAME_SHA_MANIFEST`
- `STATUS_BY_SAME_SHA_MANIFEST`

Los JSON bajo `output/evidence/runtime/stage-6/` son productores intermedios mutables. Sólo el manifiesto correlacionado, con árbol limpio, mismo SHA y checksums, tiene autoridad de cierre.

## Reproducción

Usar Node `24.19.0`, pnpm `11.19.0`, dependencias congeladas y un único `STAGE6_RUN_ID`:

```powershell
pnpm test:compat
pnpm test:a11y
pnpm test:perf
pnpm test:load
```

Los runners locales sólo pueden usar loopback y datos sintéticos. Cualquier request externa, ruta API desconocida, evidencia sensible o inventario incompleto invalida el resultado.

## Compatibilidad y responsive

El productor debe acreditar:

- Chromium, Firefox y WebKit;
- siete viewports canónicos: `320x568`, `375x667`, `390x844`, `667x375`, `768x1024`, `1334x750` y `1440x900`;
- inventario exacto por motor: producto, captura de pago, validación, resumen, pendiente, desconocido, aprobado y declinado/error;
- cero overflow horizontal y target táctil mínimo de 48 px;
- cero requests externas y cero APIs desconocidas.

## Accesibilidad

La automatización debe recorrer las 14 superficies canónicas, ejecutar axe-core, comprobar IDs DOM únicos, foco/teclado, Escape y restauración al invocador, reduced motion y ausencia de red externa.

La revisión humana se rige por `docs/verification/manual-accessibility.md` y su contrato JSON v2. Debe acreditar cuatro casos, 17 comprobaciones y la revisión de todos los resultados `incomplete` de axe sobre el mismo SHA. Sin evidencia manual válida, el estado permanece `NOT_RUN_MANUAL_REQUIRED`; nunca se infiere de axe.

## Rendimiento

El productor debe usar Lighthouse directo con configuración móvil versionada y comprobar, como mínimo:

- producto y resultado final en primera visita y repetición;
- transición y estabilidad de resumen mediante User Flow;
- tres muestras medidas por distribución;
- LCP menor de 2500 ms y CLS menor de 0.1 donde la modalidad los expone;
- asset canónico dentro de presupuesto;
- cero requests externas y artefactos HTML crudos no persistidos.

Las métricas de laboratorio no sustituyen LCP/CLS/INP P75 de campo. La ausencia de telemetría de campo debe conservarse explícitamente como límite, no como PASS inferido.

## Mapeo de evidencia

| ID           | Fuente canónica                            | Estado                        |
| ------------ | ------------------------------------------ | ----------------------------- |
| `ART-VER-09` | `compatibility.json`                       | `STATUS_BY_SAME_SHA_MANIFEST` |
| `ART-VER-10` | `accessibility.json` + evidencia manual v2 | `STATUS_BY_SAME_SHA_MANIFEST` |
| `ART-VER-11` | `performance.json` + `load.json`           | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-25`  | Motores y versiones                        | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-26`  | Viewports e inventario de estados          | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-27`  | Axe y contratos automáticos                | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-28`  | Revisión manual v2                         | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-29`  | Lighthouse y budgets                       | `STATUS_BY_SAME_SHA_MANIFEST` |
| `EVD-E6-30`  | Perfiles y escenarios de carga             | `STATUS_BY_SAME_SHA_MANIFEST` |

El reporte final y la rúbrica sólo pueden citar estos estados a través del mismo manifiesto same-SHA.
