import { loadAppConfig } from '../configuration/app-config';
import { createCatalogRepository } from './catalog-repository.factory';
import { createProductSeed } from './product-seed';

const main = async (): Promise<void> => {
  const config = loadAppConfig(process.env);
  const repository = createCatalogRepository(config);
  const seed = createProductSeed(config.productSeedId, config.publicAssetOrigin);
  const result = await repository.seedIfAbsent(seed);
  if (!result.ok) {
    throw new Error('SEED_FAILED');
  }
  process.stdout.write(`SEED_STATUS=${result.value}\n`);
};

void main();
