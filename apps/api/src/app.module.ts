import { MiddlewareConsumer, Module, type NestModule } from '@nestjs/common';
import { CATALOG_REPOSITORY, type CatalogRepository } from './application/ports/catalog-repository';
import { GetProductAvailability } from './application/use-cases/get-product-availability';
import {
  APP_CONFIG,
  loadAppConfig,
  type AppConfig,
} from './infrastructure/configuration/app-config';
import { SafeLogger } from './infrastructure/logging/safe-logger';
import { CatalogSeedService } from './infrastructure/persistence/catalog-seed.service';
import { createCatalogRepository } from './infrastructure/persistence/catalog-repository.factory';
import { DocsController } from './interfaces/http/controllers/docs.controller';
import { HealthController } from './interfaces/http/controllers/health.controller';
import { ProductsController } from './interfaces/http/controllers/products.controller';
import { CorrelationMiddleware } from './interfaces/http/middleware/correlation.middleware';
import { RequestLoggingMiddleware } from './interfaces/http/middleware/request-logging.middleware';

@Module({
  controllers: [DocsController, HealthController, ProductsController],
  providers: [
    { provide: APP_CONFIG, useFactory: (): AppConfig => loadAppConfig(process.env) },
    {
      provide: CATALOG_REPOSITORY,
      inject: [APP_CONFIG],
      useFactory: (config: AppConfig): CatalogRepository => createCatalogRepository(config),
    },
    {
      provide: GetProductAvailability,
      inject: [CATALOG_REPOSITORY],
      useFactory: (repository: CatalogRepository): GetProductAvailability =>
        new GetProductAvailability(repository),
    },
    {
      provide: SafeLogger,
      inject: [APP_CONFIG],
      useFactory: (config: AppConfig): SafeLogger =>
        new SafeLogger('checkout-api', config.appEnvironment, '0.1.0'),
    },
    CatalogSeedService,
    CorrelationMiddleware,
    RequestLoggingMiddleware,
  ],
})
export class AppModule implements NestModule {
  public configure(consumer: MiddlewareConsumer): void {
    consumer.apply(CorrelationMiddleware, RequestLoggingMiddleware).forRoutes('*');
  }
}
