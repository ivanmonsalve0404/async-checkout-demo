import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type { CatalogRepository } from '../../application/ports/catalog-repository';
import type { AppConfig } from '../configuration/app-config';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';
import { InMemoryCatalogRepository } from './in-memory-catalog.repository';

export const createCatalogRepository = (config: AppConfig): CatalogRepository => {
  if (config.dataAdapter === 'memory') {
    return new InMemoryCatalogRepository();
  }

  const lowLevelClient = new DynamoDBClient({
    endpoint: config.dynamoDbEndpoint,
    region: 'us-east-1',
    credentials: { accessKeyId: 'local', secretAccessKey: 'local' },
  });
  return new DynamoDbCatalogRepository(
    DynamoDBDocumentClient.from(lowLevelClient, {
      marshallOptions: { removeUndefinedValues: true },
    }),
    config.catalogTableName,
  );
};
