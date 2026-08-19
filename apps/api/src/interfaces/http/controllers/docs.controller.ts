import { Controller, Get, Header } from '@nestjs/common';
import { existsSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const bundledContract = join(__dirname, 'openapi.yaml');
const sourceContract = resolve(__dirname, '../../../../../..', 'output/architecture/openapi.yaml');
const openApi = readFileSync(
  existsSync(bundledContract) ? bundledContract : sourceContract,
  'utf8',
);

@Controller('api/docs')
export class DocsController {
  @Get()
  @Header('Cache-Control', 'public, max-age=300')
  @Header('Content-Disposition', 'inline; filename="openapi.yaml"')
  @Header('Content-Type', 'application/yaml; charset=utf-8')
  public getDocumentation(): string {
    return openApi;
  }
}
