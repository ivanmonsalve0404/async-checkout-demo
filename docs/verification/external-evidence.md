<!-- stage6-external-evidence-protocol: v1.0.0 -->

# Protocolo de evidencia externa autorizada E6

| Campo                      | Valor                                        |
| -------------------------- | -------------------------------------------- |
| Schema                     | `async-checkout-stage6-external-evidence` v1 |
| Protocolo                  | `1.0.0`                                      |
| Fuente                     | JSON externo versionado y sanitizado         |
| Autoridad en ausencia      | `NOT_RUN_AUTH_REQUIRED`                      |
| Datos sensibles permitidos | 0                                            |

Este protocolo importa observaciones de ejecuciones autorizadas separadas. No concede autorización,
no ejecuta red externa y no hace que la verificación local o CI contacte un target. El JSON fuente
puede incluir cualquier subconjunto no vacío de tres capacidades independientes; una capacidad
ausente conserva `NOT_RUN_AUTH_REQUIRED` y una fuente configurada inválida falla cerrada.

## AUTH-E6-01 — target efímero propio y UAT-33

El ejecutor autorizado confirma la propiedad y vigencia del target `ENV-E6-QA`, limita las requests al
máximo aprobado y registra únicamente hashes. La matriz ordenada es:

1. `AUTH01-E6-01`: HTTP responde 301 o 308 hacia HTTPS.
2. `AUTH01-E6-02`: el documento HTTPS responde 200.
3. `AUTH01-E6-03`: el navegador observa cero requests de mixed content.

El JSON no guarda URL, hostname, headers crudos ni contenido. Registra hash SHA-256 del origin y del
reporte sanitizado, cero requests fuera de allowlist, cero requests al proveedor y cero requests a
producción. Sólo esa matriz exacta puede promover `UAT-33`.

## AUTH-E6-02 — smoke mínimo de sandbox

Antes de ejecutar, el responsable obtiene autorización versionada, verifica `environment=sandbox`,
host allowlisted, kill switch, volumen máximo y logging redactado. Usa una referencia con prefijo
`e6-` y `runId` propio; el JSON conserva sólo su hash. La matriz ordenada es:

1. `AUTH02-E6-01`: configuración y aceptaciones aplicables observadas.
2. `AUTH02-E6-02`: método de pago de prueba autorizado creado desde el cliente.
3. `AUTH02-E6-03`: transacción local PENDING creada antes de llamar al proveedor.
4. `AUTH02-E6-04`: una transacción sandbox creada con referencia propia.
5. `AUTH02-E6-05`: estado consultado por ID/referencia hasta el estado observado.
6. `AUTH02-E6-06`: monto, moneda y referencia validados antes de reconciliar.
7. `AUTH02-E6-07`: errores mapeados sin filtrar secretos ni payloads.
8. `AUTH02-E6-08`: consulta/reconciliación repetida sin efectos duplicados.

El resultado puede ser APPROVED, DECLINED, ERROR o PENDING según la capacidad real del sandbox; no se
fuerza un estado. Para PASS se exigen cero llamadas a producción, cero cambios globales, cero escape
de allowlist, consistencia provider/local, efectos duplicados cero y prueba de que el adapter puede
deshabilitarse por configuración. Sólo esta matriz promueve `EVD-E6-24` y `ART-VER-07`.

## AUTH-E6-03 — headers y ZAP baseline pasivo

La autorización vincula el target efímero propio por hash y limita el número de requests. Los headers
críticos se registran como seis checks ordenados: Content-Security-Policy, Referrer-Policy,
X-Content-Type-Options, protección de clickjacking, Permissions-Policy y Strict-Transport-Security.
Las respuestas sensibles deben usar no-store y el conteo de headers críticos faltantes debe ser cero.

ZAP se ejecuta en modo `PASSIVE_BASELINE`; active scan permanece prohibido sin `AUTH-E6-04`. El resumen
incluye hashes de ruleset/reporte, versión de herramienta, endpoints propios inspeccionados y conteos
por severidad. Todos los alerts se revisan; críticos confirmados, altos confirmados, endpoints propios
fuera de scope, requests fuera de allowlist, requests al proveedor/producción, redirects externos y
requests activas deben ser cero. Esta evidencia promueve `EVD-E6-33` y completa la parte edge de
`EVD-E6-34`.

## Ingestión y sanitización

El commit del JSON debe ser exactamente el candidato. El `runId` de la ejecución externa debe ser
válido y distinto del `runId` de ingestión; el productor añade `ingestedByRunId` sin reescribir la
fuente. El checksum de este protocolo, del schema y del JSON se registra en cada resumen.

Sólo se aceptan hashes, contadores acotados, enums, aliases seguros y timestamps UTC. Se prohíben URLs,
hostnames, IDs de transacción, referencias crudas, respuestas del proveedor, reportes crudos,
credenciales, datos de pago y PII. El canal CI opcional materializa el JSON sanitizado desde
`STAGE6_EXTERNAL_EVIDENCE_B64` en el directorio temporal del runner y expone únicamente su path mediante
`STAGE6_EXTERNAL_EVIDENCE`.

El workflow de `pull_request` no ingiere esta autoridad versionada: un PR valida el código y conserva el
gate externo como `NOT_RUN_AUTH_REQUIRED`. La ingestión queda reservada a ejecuciones no-PR sobre el SHA
exacto, evitando aplicar evidencia persistida de otro candidato al merge commit temporal.

Todos los timestamps usan la forma UTC canónica `YYYY-MM-DDTHH:mm:ss.sssZ`, incluidos milisegundos no
cero cuando correspondan; fechas inexistentes u offsets se rechazan. Todos los contadores quedan entre
0 y 100 (o entre 1 y 100 cuando el check requiere actividad). ZAP debe declarar exactamente la versión
allowlisted `2.16.1`.

La ingestión acepta un único archivo local regular de máximo 131072 bytes. Rechaza symlinks, directorios,
UNC, device paths, named pipes, flags vacíos/duplicados y whitespace alrededor del path. El JSON se
decodifica como UTF-8 estricto, rechaza claves duplicadas y escanea el buffer crudo y sus valores
decodificados antes de validar el schema; tampoco persiste el buffer fuente.

`AUTH-E6-04` no es concedida por este protocolo. DAST activo sigue prohibido por defecto y no es
requisito de PASS de etapa 6.
