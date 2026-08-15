# Toolchain congelado — etapa 4

Fecha de verificación: 2026-08-14.

| Componente            |         Versión fijada | Autoridad                                      |
| --------------------- | ---------------------: | ---------------------------------------------- |
| Node.js               |              `24.19.0` | `.nvmrc`, `.node-version`, `package.json` y CI |
| pnpm                  |              `11.19.0` | `packageManager`, `engines`, workspace y CI    |
| TypeScript            |                `5.9.3` | manifest raíz                                  |
| React                 |               `19.2.8` | manifest web                                   |
| Vite                  |                `8.2.1` | manifest web                                   |
| Redux Toolkit         |               `2.12.0` | manifest web                                   |
| NestJS                |               `11.2.1` | manifest API                                   |
| Jest                  |               `30.4.2` | manifests web/API                              |
| Playwright Test       |               `1.61.1` | manifest raíz; browser smoke                   |
| OpenAPI TypeScript    |               `7.13.0` | manifest contracts                             |
| AWS CDK library / CLI | `2.265.0` / `2.1136.0` | manifest infra                                 |

`pnpm-lock.yaml` es el único lockfile y la autoridad de resolución transitiva. `scripts/check-workspace.mjs` rechaza otro runtime o package manager. No se permiten rangos en dependencias directas.

La instalación reproducible es `pnpm install --frozen-lockfile`. Actualizar cualquier versión exige cambio explícito, regeneración contractual, auditoría, tests, build, synth y smoke.
