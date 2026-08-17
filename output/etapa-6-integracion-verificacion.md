# Etapa 6 — Integración y verificación

<!-- stage6-status-authority: ART-VER-18 SAME_SHA_RUNTIME_MANIFEST -->

| Metadato           | Autoridad                     |
| ------------------ | ----------------------------- |
| Run ID             | `RUN_ID_BY_SAME_SHA_MANIFEST` |
| Commit candidato   | `SHA_BY_SAME_SHA_MANIFEST`    |
| Estado del reporte | `STATUS_BY_SAME_SHA_MANIFEST` |

Este documento versionado describe cómo interpretar el cierre. Los resultados efectivos, sus checksums y los gates pertenecen exclusivamente al manifiesto runtime producido sobre el mismo SHA.

## 1. Resumen ejecutivo

`EVD-E6-01` vincula la entrada reconciliada con la campaña. El resultado ejecutivo se consulta como `STATUS_BY_SAME_SHA_MANIFEST`; este texto no convierte controles bloqueados o externos en aprobados.

## 2. Estado de entrada y prerrequisitos

`EVD-E6-02` identifica el candidato y `EVD-E6-03` demuestra la reproducción limpia. Ambos conservan `STATUS_BY_SAME_SHA_MANIFEST`, de modo que una ejecución local no suplanta el freeze exigido en CI.

## 3. Commit candidato y baseline

El SHA efectivo se obtiene mediante `SHA_BY_SAME_SHA_MANIFEST`, junto con lockfile, árbol y toolchain del mismo snapshot. Su evaluación queda en `STATUS_BY_SAME_SHA_MANIFEST` y nunca se copia aquí como literal mutable.

## 4. Entornos, autorizaciones y datos de prueba

`AUTH-E6-01`, `AUTH-E6-02`, `AUTH-E6-03` y `AUTH-E6-04` gobiernan toda mutación externa. `STATUS_BY_SAME_SHA_MANIFEST` conserva red externa denegada por defecto, datos sintéticos y ejecución local aislada.

## 5. Plan de verificación y trazabilidad

`ART-VER-01` define la campaña y `ART-VER-03` enlaza requisitos, pruebas, UAT y evidencias. Su completitud se resuelve por `STATUS_BY_SAME_SHA_MANIFEST`, sin duplicar una segunda fuente de verdad.

## 6. Verificación estática

`EVD-E6-04` cubre formato, lint, tipos, build y guardas estructurales. El manifiesto registra el comando y asigna `STATUS_BY_SAME_SHA_MANIFEST`; este reporte sólo preserva el vínculo auditable.

## 7. Unit tests y cobertura frontend

`EVD-E6-06` representa la suite web y `EVD-E6-08` sus cuatro métricas de cobertura, incluidas rutas críticas. Los conteos exactos y `STATUS_BY_SAME_SHA_MANIFEST` proceden de la ejecución del candidato.

## 8. Unit tests y cobertura backend

`EVD-E6-07` representa la suite API y `EVD-E6-09` valida el umbral por métrica y ruta crítica. Ningún resultado heredado puntúa: sólo `STATUS_BY_SAME_SHA_MANIFEST` es autoritativo.

## 9. Integración frontend/backend/data

`EVD-E6-11` comprueba repositorios y transacciones, mientras `EVD-E6-12` cubre fronteras internas y provider fake. La integración efectiva mantiene `STATUS_BY_SAME_SHA_MANIFEST` en el cierre.

## 10. OpenAPI y contract testing

`EVD-E6-05` exige OpenAPI válido, cliente generado alineado y deriva contractual cero. El checksum y `STATUS_BY_SAME_SHA_MANIFEST` se toman del manifiesto asociado al candidato.

## 11. Fake provider y E2E

`EVD-E6-13` cubre los escenarios deterministas del fake y `EVD-E6-14` los smokes heredados. Sus matrices completas, sin red externa, determinan `STATUS_BY_SAME_SHA_MANIFEST`.

## 12. Integración sandbox

`EVD-E6-24` permanece sometida a `AUTH-E6-02`; sin autorización no se emite tráfico y el runtime conserva el estado aplicable. `STATUS_BY_SAME_SHA_MANIFEST` nunca presenta esa ausencia como prueba superada.

## 13. Integridad, concurrencia e idempotencia

`EVD-E6-15`, `EVD-E6-16`, `EVD-E6-17`, `EVD-E6-18`, `EVD-E6-19` y `EVD-E6-20` cubren efectos únicos, liberación, unknown, replay, último stock y quote. La matriz exacta decide `STATUS_BY_SAME_SHA_MANIFEST`.

## 14. Resiliencia y recovery

`EVD-E6-21`, `EVD-E6-22` y `EVD-E6-23` verifican refresh, pending y multitab sin duplicados. Sus observaciones de recuperación quedan referenciadas por `STATUS_BY_SAME_SHA_MANIFEST`.

## 15. Cross-browser y responsive

`EVD-E6-25` exige Chromium, Firefox y WebKit; `EVD-E6-26` exige los siete viewports congelados. Motores, superficies y conteos reales alimentan `STATUS_BY_SAME_SHA_MANIFEST`.

## 16. Accesibilidad

`EVD-E6-27` registra axe y contratos automáticos; `EVD-E6-28` requiere además revisión humana válida. `STATUS_BY_SAME_SHA_MANIFEST` mantiene la parte manual separada y usa `NOT_RUN_MANUAL_REQUIRED` cuando falta, nunca un PASS artificial.

## 17. Rendimiento y carga

`EVD-E6-29` contiene laboratorio y presupuestos; `EVD-E6-30` contiene carga local acotada e invariantes. Medianas, perfiles y límites respaldan `STATUS_BY_SAME_SHA_MANIFEST` sin afirmar datos de campo.

## 18. Seguridad y privacidad

`EVD-E6-31`, `EVD-E6-32`, `EVD-E6-33`, `EVD-E6-34` y `EVD-E6-35` separan secretos, supply chain, DAST autorizado, controles HTTP y fugas. `STATUS_BY_SAME_SHA_MANIFEST` respeta los límites de autorización y sanitización.

## 19. Observabilidad

La evidencia de observability comparte `EVD-E6-35`: correlación, redacción, almacenamiento y red se verifican sin payloads sensibles. El resultado técnico se delega a `STATUS_BY_SAME_SHA_MANIFEST`.

## 20. UAT

`EVD-E6-36` agrega la matriz `UAT-01..48` sin fijar estados mutables en este reporte. Cada fila usa `STATUS_BY_SAME_SHA_MANIFEST`; UAT manual o externa conserva su requisito propio hasta contar con evidencia válida.

## 21. Defectos, regresiones y flakiness

`EVD-E6-37` controla P0/P1 abiertos y `EVD-E6-38` controla retries y flakiness crítica. Causa, fix y reejecución permanecen trazados, pero el cierre depende de `STATUS_BY_SAME_SHA_MANIFEST`.

## 22. Evidencias e índice

`ART-VER-16` enumera exactamente cuarenta evidencias y dieciocho artefactos sanitizados. Run, SHA, rutas y checksums se resuelven en el manifiesto; la integridad del índice usa `STATUS_BY_SAME_SHA_MANIFEST`.

## 23. Scorecard de rúbrica

`EVD-E6-39` alimenta `RUB-BASE-01..06` y `RUB-BONUS-01..06` con cálculo todo-o-cero. El puntaje se deriva del cierre como `STATUS_BY_SAME_SHA_MANIFEST`; el bonus nunca compensa base ausente.

## 24. Evaluación GATE-E6-01

`GATE-E6-01` exige baseline, pruebas, cobertura, contratos, fake, smokes, secretos y defectos críticos en regla. Su único valor efectivo es `STATUS_BY_SAME_SHA_MANIFEST`; no admite conditional go.

## 25. Evaluación GATE-E6-02

`GATE-E6-02` agrupa integridad, recovery, compatibilidad, accesibilidad, rendimiento y seguridad. `STATUS_BY_SAME_SHA_MANIFEST` sólo puede ser condicional por una verificación externa no autorizada, nunca por un fallo local.

## 26. Evaluación GATE-E6-03

`GATE-E6-03` combina UAT, regresión, artefactos, evidencias, rúbrica y autorizaciones. `STATUS_BY_SAME_SHA_MANIFEST` distingue PASS, conditional go y fail sin habilitar publicación indebidamente.

## 27. Release candidate y handoff a etapa 7

`EVD-E6-40` publica gates y `releasePolicy` desde el manifiesto del mismo candidato. `STATUS_BY_SAME_SHA_MANIFEST` habilita Etapa 7 completa sólo con PASS; cualquier estado condicional limita el handoff a pre-release no público.
