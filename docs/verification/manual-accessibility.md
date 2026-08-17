# Etapa 6 — Protocolo manual de accesibilidad v2

## Control

| Campo                 | Valor                                                                       |
| --------------------- | --------------------------------------------------------------------------- |
| Evidencia             | `EVD-E6-28`                                                                 |
| Estado                | `NOT_RUN_MANUAL_REQUIRED`                                                   |
| Contrato de ingestión | `urn:async-checkout-demo:stage6:a11y-manual-evidence:2`                     |
| Versión del protocolo | `E6-A11Y-MANUAL-2`                                                          |
| Alcance               | Aplicación local con fake, datos sintéticos y red externa denegada          |
| Exclusión             | Semántica del componente alojado real: `NOT_RUN_AUTH_REQUIRED` por `ADR-09` |
| Candidato             | El `commitSha` exacto revisado manualmente                                  |
| Ejecución fuente      | `runId` único del recorrido humano; se resume como `sourceManualRunId`      |
| Campaña de ingestión  | Run actual separado; se resume como `ingestedByRunId`                       |
| Declaración normativa | `NO_WCAG_CONFORMANCE_CLAIM`                                                 |

Este documento define el procedimiento autoritativo. No registra una ejecución ni declara un resultado aprobado. `EVD-E6-28` sólo puede evaluarse después de ejecutar los cuatro casos completos sobre un `commitSha` fijo y revisar todos los resultados axe `incomplete` correlacionados. Una campaña posterior puede ingerir esa evidencia únicamente para el mismo commit y si reproduce exactamente el inventario axe.

## Preflight

Antes de probar:

1. fijar el `commitSha` revisado y generar un `runId` único para la ejecución manual fuente;
2. calcular `protocolDocumentSha256` sobre este archivo ya formateado;
3. registrar UTC, alias del revisor y versiones exactas de Windows, navegador y lector;
4. usar NVDA o Narrator y únicamente producto, cliente y dirección sintéticos;
5. confirmar fake local, red externa denegada y cero requests desconocidas;
6. no capturar ni escribir PAN, CVC, token, secreto, correo, teléfono o PII en resultados, screenshots, traces o videos;
7. obtener del reporte automático asociado a la ejecución manual fuente el inventario exacto de superficies y resultados axe `incomplete`;
8. al ingerir después, registrar el run actual por separado y exigir el mismo commit, hashes e inventario axe.

## Contrato de evidencia v2

El archivo externo de evidencia debe cumplir `scripts/stage6/a11y/manual-evidence.schema.json` y estas reglas:

- `schemaId`, `schemaVersion: 2`, `stage: 6` y `protocolVersion` son constantes;
- `protocolDocumentSha256` debe coincidir con el SHA-256 actual de este documento;
- `commitSha` identifica el candidato revisado y debe coincidir exactamente con la campaña que ingiere;
- el `runId` del JSON es el identificador único de la ejecución manual fuente y no se reescribe ni necesita igualar el run posterior de CI;
- `executedAtUtc`, `reviewerAlias`, `browser` y `screenReader` son obligatorios;
- `cases` contiene exactamente, en este orden, `A11Y-MAN-01`, `A11Y-MAN-02`, `A11Y-MAN-03` y `A11Y-MAN-04`;
- cada caso usa su `evidenceId` exacto y el inventario de checks descrito abajo, sin faltantes, extras ni reordenamiento;
- cada caso y check registra `status: PASS|FAIL` y un `actualResult` factual de 24–500 caracteres en una sola línea;
- el `status` del caso se deriva de sus checks: sólo es `PASS` cuando todos sus checks son `PASS`;
- cada caso `FAIL` incluye un `defectId` con formato `DEF-E6-*`;
- `axeIncompleteReviews` reproduce exactamente el inventario correlacionado definido en la sección correspondiente;
- el `status` raíz se deriva de los cuatro casos y de todas las revisiones axe;
- `containsSensitiveData: false` es obligatorio, pero no sustituye la validación del contenido.

El resumen seguro mezcla las ejecuciones de forma explícita: `sourceManualRunId` conserva el `runId` del JSON humano e `ingestedByRunId` registra la campaña actual. La evidencia manual sólo es reutilizable cuando `commitSha`, schema, protocolo e inventario axe siguen siendo exactos; cambiar cualquiera de ellos invalida la ingestión.

La ingestión rechaza resultados con PAN-like de 13–19 dígitos, teléfonos, correos, claves privadas, valores etiquetados como token/secreto/clave, CVC/CVV/código de seguridad contextual o expiración contextual. El reporte promovido conserva únicamente estados, IDs seguros, conteos y hashes; nunca copia `actualResult`, la ruta del archivo ni el JSON raw.

## `A11Y-MAN-01` — Semántica y anuncios con lector

- Evidencia exacta: `EVD-E6-28/A11Y-MAN-01`.
- Configuración: NVDA o Narrator, navegador registrado y zoom 100 %.

| Check             | Significado                           | Procedimiento reproducible                                                                                                                                                                                  | Resultado esperado                                                                                                                                                                              |
| ----------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A11Y-MAN-01-C01` | Estructura, nombre, rol y comprensión | Abrir producto; recorrer landmarks, headings, precio, stock, instrucciones y CTA con el lector; abrir checkout y recorrer captura, cliente, aceptaciones y resumen sin usar el puntero.                     | Orden y contenido comprensibles; headings y landmarks identificables; cada control comunica nombre, rol, estado, valor e instrucciones pertinentes sin ambigüedad ni duplicación.               |
| `A11Y-MAN-01-C02` | Anuncios, timeout y recuperación      | Enviar el checkout con fake; escuchar `PENDING` y un resultado final; repetir la consulta sin reenviar; provocar timeout o expiración y activar la recuperación ofrecida.                                   | Cada transición se anuncia una vez; el timeout se comunica antes o al ocurrir, explica su efecto y ofrece continuar, reintentar con seguridad o reiniciar sin estado contradictorio.            |
| `A11Y-MAN-01-C03` | Errores e instrucciones asociados     | En captura, cliente y aceptaciones, intentar continuar con datos omitidos o inválidos; leer el resumen y navegar desde cada mensaje hasta el control relacionado.                                           | El resumen se anuncia; cada error identifica el campo, explica la corrección y está asociado programáticamente sin perder el contexto.                                                          |
| `A11Y-MAN-01-C04` | Datos sensibles y reingreso necesario | Durante captura y navegación con lector, revisar lo anunciado dentro y fuera del control enfocado; avanzar, volver, cerrar/reabrir y recuperar una sesión; comparar qué datos permitidos solicita de nuevo. | No reaparece contenido sensible fuera del control activo; los valores sensibles se limpian; los datos permitidos ya entregados no se solicitan otra vez salvo necesidad explícita y comunicada. |

## `A11Y-MAN-02` — Teclado y foco

- Evidencia exacta: `EVD-E6-28/A11Y-MAN-02`.
- Configuración: sólo teclado, lector activo y zoom 100 %.

| Check             | Significado                            | Procedimiento reproducible                                                                                                                | Resultado esperado                                                                                                                                        |
| ----------------- | -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A11Y-MAN-02-C01` | Foco inicial del diálogo               | Enfocar “Comprar” con teclado y activarlo; no pulsar otra tecla después de abrir.                                                         | El fondo queda inerte y el foco entra al diálogo en su heading o punto inicial aprobado, con nombre accesible del paso actual.                            |
| `A11Y-MAN-02-C02` | Contención y orden de tabulación       | Recorrer todos los elementos con Tab hasta volver al primero; repetir con Shift+Tab desde el primero hasta el último.                     | El orden es lógico en ambas direcciones; el foco permanece dentro del diálogo y no alcanza contenido inerte.                                              |
| `A11Y-MAN-02-C03` | Foco visible y no oculto               | Avanzar por campos, enlaces, checkboxes y CTA en cada paso, desplazando el contenedor sólo cuando sea necesario.                          | El indicador de foco siempre es perceptible, no queda cubierto por sticky UI, teclado virtual o límites del diálogo y llega a cada acción habilitada.     |
| `A11Y-MAN-02-C04` | Foco al validar y corregir             | Provocar un error en cada paso; comprobar el destino inmediato del foco; seguir el orden hasta el campo inválido, corregirlo y continuar. | El foco llega al resumen o control aprobado, el error se anuncia, la corrección conserva contexto y la transición posterior enfoca el heading correcto.   |
| `A11Y-MAN-02-C05` | Escape, retorno y transición asíncrona | Cerrar con Escape, confirmar retorno, reabrir, completar los pasos y observar el foco durante `PENDING` y el resultado final.             | Escape cierra y devuelve el foco al CTA “Comprar” actualmente montado; cada transición de paso, pending y final mueve el foco al heading correspondiente. |

## `A11Y-MAN-03` — Zoom y reflow

- Evidencia exacta: `EVD-E6-28/A11Y-MAN-03`.
- Configuración: zoom 200 %; viewport 1280×720 y ancho equivalente a 320 CSS px.

| Check             | Significado                             | Procedimiento reproducible                                                                                                                                                          | Resultado esperado                                                                                                                                                                                       |
| ----------------- | --------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A11Y-MAN-03-C01` | Flujo completo a zoom 200 %             | En 1280×720 y zoom 200 %, recorrer producto, captura, cliente, aceptaciones, resumen, error, `PENDING` y resultado final.                                                           | Ningún contenido, campo, mensaje o acción indispensable se pierde; el orden visual y de lectura conserva la secuencia del flujo.                                                                         |
| `A11Y-MAN-03-C02` | Reflow a 320 CSS px                     | Reducir el área de contenido al equivalente de 320 CSS px y repetir las mismas superficies y estados sin cambiar el zoom.                                                           | El contenido refluye en una sola dimensión; no exige desplazamiento horizontal de página para leer texto o completar una acción.                                                                         |
| `A11Y-MAN-03-C03` | Alcance, scroll y target size           | Desde cada superficie, usar sólo teclado y el scroll previsto para alcanzar campos, errores, enlaces y CTA; inspeccionar el área activable de cada target en móvil y a 200 %.       | Todos los controles y mensajes son alcanzables y visibles; ningún foco queda fuera de pantalla o atrapado; cada target cumple el tamaño o separación aprobados sin activaciones adyacentes accidentales. |
| `A11Y-MAN-03-C04` | Legibilidad y contraste en color normal | Antes del zoom, revisar en color normal el contraste de texto, controles y foco; luego inspeccionar headings, precios, labels, ayudas, errores, botones y estados en ambos tamaños. | Texto y controles no se solapan ni truncan; texto, límites de controles e indicador de foco conservan contraste suficiente en color normal; forced-colors no sustituye esta comprobación.                |

## `A11Y-MAN-04` — Forced colors

- Evidencia exacta: `EVD-E6-28/A11Y-MAN-04`.
- Configuración: Windows forced-colors/alto contraste activo y navegación sólo con teclado.

| Check             | Significado                                 | Procedimiento reproducible                                                                                                                        | Resultado esperado                                                                                                                                                        |
| ----------------- | ------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `A11Y-MAN-04-C01` | Controles e indicador de foco visibles      | Recorrer producto, diálogo, campos, checkboxes, enlaces y botones con Tab y Shift+Tab en forced-colors.                                           | Cada control conserva límites perceptibles; el foco se distingue del estado normal y no desaparece sobre fondo, borde o elemento deshabilitado.                           |
| `A11Y-MAN-04-C02` | Estado no comunicado sólo por color o icono | Revisar stock, selección, validación, loading, `PENDING`, aprobado, declinado y error ocultando mentalmente color e iconografía por separado.     | Cada estado conserva texto o semántica suficiente: ni el color ni un icono son el único portador; cualquier icono informativo tiene nombre accesible o texto equivalente. |
| `A11Y-MAN-04-C03` | Bordes, enlaces y errores discernibles      | Inspeccionar separadores, campos, enlaces legales, resumen de errores y mensajes inline; alternar foco entre elementos adyacentes.                | Bordes y enlaces siguen distinguibles; errores conservan indicador y texto; contenido y controles no se fusionan con el fondo.                                            |
| `A11Y-MAN-04-C04` | CTA críticas operables                      | Activar con teclado comprar, tokenizar/continuar, guardar entrega, aceptar contratos, pagar, reintentar/volver y cerrar cuando estén disponibles. | Cada CTA habilitada responde una sola vez, muestra un estado perceptible y no depende de puntero, hover, imagen de fondo ni color.                                        |

## Inventario automático y revisión axe `incomplete`

El runner automatizado cubre exactamente 14/14 superficies; esta enumeración define cobertura, no un resultado de ejecución:

1. `product`;
2. `checkout-payment`;
3. `payment-validation`;
4. `checkout-customer`;
5. `customer-validation`;
6. `checkout-acceptances`;
7. `acceptances-validation`;
8. `checkout-summary`;
9. `transaction-pending`;
10. `transaction-unknown`;
11. `transaction-approved`;
12. `transaction-declined`;
13. `transaction-error`;
14. `transaction-network-error`.

Para producir `axeIncompleteReviews`:

1. tomar todos los objetos `automated.axeScans[*].incomplete` asociados al `runId` manual fuente;
2. agrupar por `ruleId`, ordenar los IDs, ordenar sus superficies y sumar `nodeCount`;
3. crear exactamente una revisión por regla, en ese orden, con los mismos `ruleId`, `surfaces` y `nodeCount`;
4. inspeccionar todos los nodos de todas las superficies citadas según la ayuda oficial de la regla;
5. registrar `status` y un `actualResult` factual y sanitizado;
6. usar `FAIL` y `defectId` si cualquier nodo constituye una violación; usar `PASS` sólo si todos los nodos agrupados fueron revisados y ninguno constituye una violación.

Una regla faltante, extra, reordenada o con superficies/conteos distintos invalida la ingestión. Si el inventario automático es vacío, `axeIncompleteReviews` también debe ser exactamente vacío; no se inventa una revisión.

En cada ingestión posterior, el predicado vuelve a derivar este inventario desde los 14 scans de la campaña actual. La evidencia fuente sólo se acepta si reglas, superficies y conteos coinciden exactamente; no se reutiliza por similitud ni sólo por tener cuatro flags en `PASS`.

## Plantilla de control no ejecutada

| Caso          | Evidencia exacta        | Checks exactos | Estado inicial            | Resultado actual                         |
| ------------- | ----------------------- | -------------- | ------------------------- | ---------------------------------------- |
| `A11Y-MAN-01` | `EVD-E6-28/A11Y-MAN-01` | 4              | `NOT_RUN_MANUAL_REQUIRED` | Requiere revisión humana con lector      |
| `A11Y-MAN-02` | `EVD-E6-28/A11Y-MAN-02` | 5              | `NOT_RUN_MANUAL_REQUIRED` | Requiere recorrido humano sólo teclado   |
| `A11Y-MAN-03` | `EVD-E6-28/A11Y-MAN-03` | 4              | `NOT_RUN_MANUAL_REQUIRED` | Requiere inspección humana de reflow     |
| `A11Y-MAN-04` | `EVD-E6-28/A11Y-MAN-04` | 4              | `NOT_RUN_MANUAL_REQUIRED` | Requiere inspección humana forced-colors |

## Derivación y salida

- `screenReader` se deriva de `A11Y-MAN-01` y `A11Y-MAN-02`;
- `zoom200Reflow` se deriva de `A11Y-MAN-03`;
- `forcedColors` se deriva de `A11Y-MAN-04`;
- `axeIncompleteReview` se deriva de todas las revisiones correlacionadas;
- el resultado raíz sólo puede ser `PASS` cuando los cuatro casos y todas las revisiones son `PASS`; cualquier fallo produce `FAIL`;
- la ausencia del JSON conserva `NOT_RUN_MANUAL_REQUIRED`; nunca se convierte en `PASS`;
- `sourceManualRunId` identifica los hechos humanos e `ingestedByRunId` la campaña que los verificó contra el mismo commit;
- cambiar este documento cambia `protocolDocumentSha256` e invalida cualquier evidencia firmada con el hash anterior.

No usar evidencia automática, tests JSDOM, Lighthouse o una declaración vacía para promover un caso manual.
