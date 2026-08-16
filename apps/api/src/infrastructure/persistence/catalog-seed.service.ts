import { Inject, Injectable, type OnModuleInit } from '@nestjs/common';
import type { CatalogRepository } from '../../application/ports/catalog-repository';
import { CATALOG_REPOSITORY } from '../../application/ports/catalog-repository';
import type { AppConfig } from '../configuration/app-config';
import { APP_CONFIG } from '../configuration/app-config';
import { createProductSeed } from './product-seed';

@Injectable()
export class CatalogSeedService implements OnModuleInit {
  public constructor(
    @Inject(CATALOG_REPOSITORY) private readonly repository: CatalogRepository,
    @Inject(APP_CONFIG) private readonly config: AppConfig,
  ) {}

  public async onModuleInit(): Promise<void> {
    const seed = createProductSeed(
      this.config.productSeedId,
      this.config.publicAssetOrigin,
      this.config.productInitialStock,
    );
    const result = await this.repository.seedIfAbsent(seed);
    if (!result.ok) {
      throw new Error('Catalog seed could not be established');
    }
  }
}
