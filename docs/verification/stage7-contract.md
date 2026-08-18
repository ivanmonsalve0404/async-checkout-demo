# Contrato local de Etapa 7

Este contrato prepara una release sin llamar AWS ni cambiar infraestructura. Es
fail-closed: una omisión, un valor adicional, una autorización vencida, una
evidencia inconsistente o un candidato distinto produce error o `NOT_READY`.

## Autoridad de los datos

El archivo de configuración autorizado es un insumo local temporal, no un archivo
para versionar. Debe declarar exactamente:

- autorización aprobada, alcance, responsables, canal, ventana, stacks y criterios
  de aborto;
- cuenta, región y ARN de rol de mínimo privilegio;
- presupuesto máximo aprobado, umbrales y responsables de alertas;
- estrategia de dominio;
- owner y fecha de cleanup, preservando bootstrap y la release anterior;
- solo ARN de referencias de credenciales en Secrets Manager o Parameter Store;
- `containsSensitiveData: false` y ninguna credencial material.

Los alcances válidos son plan no mutante, prerelease efímera y release completa.
Los dos últimos requieren sandbox autorizado y al menos una referencia de
credencial. Una release completa requiere que la entrada de Etapa 6 sea `PASS`;
dominio propio autorizado con TLS 1.2, y una entrada condicional solo habilita la
prerelease no pública autorizada sobre dominio administrado por AWS.

## CLI local

Todas las órdenes usan `node scripts/stage7/cli.mjs`:

- `self-test` verifica contratos, invariantes, sanitización y documentos;
- `documents` verifica los catálogos y las 33 secciones;
- `build-paths` publica las rutas que debe producir el bundler sin ejecutarlo;
- `config --config <archivo>` valida y muestra únicamente un resumen sanitizado;
- `preflight --config <archivo> --e6-manifest <archivo> [--freeze <archivo>]`
  compara autorización, candidato y estado de entrada sin tocar la nube;
- `freeze --config <archivo> --e6-manifest <archivo> [--tag <tag>] --web <ruta>
--api <ruta> --worker <ruta> --iac <ruta> --public-config <ruta>
--source-artifact-id <id> --source-artifact-sha256 <sha256>
--aws-cli-version <versión> --output <ruta>` crea el manifiesto build-once con
  SHA y checksums. El tag es obligatorio sólo para release completa; una prerelease
  efímera autorizada se congela sin tag final y conserva `GATE-E6-03 = CONDITIONAL_GO`;
- `plan --preflight <archivo> [--output <ruta>]` crea el catálogo inicial sin
  convertir trabajo pendiente en éxito.

El preflight devuelve código 2 cuando la decisión es `NOT_READY`. Los checks de
cuenta, región, trust, bootstrap y cuotas permanecen `NOT_RUN` hasta que el futuro
orquestador cloud los ejecute con autorización explícita. Ningún comando local
declara un gate como aprobado.

## Freeze build-once

El freeze exige candidato limpio, SHA y árbol idénticos a la evidencia aprobada.
La release completa exige tag semántico; la prerelease efímera queda explícitamente
sin tag final. Ambos alcances fijan Node, package manager, CDK y AWS CLI, y exigen
artefactos web, API, worker e IaC ya construidos. Calcula checksum de
cada archivo o árbol, del artefacto CI fuente, lockfile, OpenAPI, cliente generado,
templates y configuración pública. Recompilar después del freeze crea un candidato
distinto: no se puede sustituir silenciosamente el contenido congelado.

El contrato esperado del bundler es:

- `output/release/build/web/**` para assets web;
- `output/release/build/api/index.js` para la Lambda HTTP;
- `output/release/build/worker/index.js` para el reconciliador;
- `output/release/build/iac/**` para templates normalizados.

## Documento final

La plantilla documental y el índice contienen marcadores, no resultados. El
manifiesto final de release es la autoridad única que debe delegar estados,
evidencias, hashes, URLs y gates a las 33 secciones antes del handoff.
