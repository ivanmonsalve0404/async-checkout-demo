import { Controller, Get, Header } from '@nestjs/common';

@Controller('api/docs')
export class DocsController {
  @Get()
  @Header('Cache-Control', 'public, max-age=300')
  @Header('Content-Type', 'text/html; charset=utf-8')
  public getDocumentation(): string {
    return '<!doctype html><html lang="es"><head><meta charset="utf-8"><title>API checkout</title></head><body><main><h1>Contrato API</h1><p>La fuente canónica está versionada en packages/contracts/openapi.yaml.</p></main></body></html>';
  }
}
