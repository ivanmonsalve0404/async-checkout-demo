import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import type { CatalogRepository } from '../../application/ports/catalog-repository';
import type { AppConfig } from '../configuration/app-config';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';
import { InMemoryCatalogRepository } from './in-memory-catalog.repository';

export const DYNAMODB_DOCUMENT_CLIENT = Symbol('DYNAMODB_DOCUMENT_CLIENT');

export const createDynamoDocumentClient = (config: AppConfig): DynamoDBDocumentClient => {
  const lowLevelClient = new DynamoDBClient(
    config.dynamoDbEndpoint === undefined
      ? { region: config.awsRegion }
      : {
          endpoint: config.dynamoDbEndpoint,
          region: config.awsRegion,
          credentials: { accessKeyId: 'local', secretAccessKey: 'local' },
        },
  );
  return DynamoDBDocumentClient.from(lowLevelClient, {
    marshallOptions: { removeUndefinedValues: true },
  });
};

export const createCatalogRepository = (
  config: AppConfig,
  client?: DynamoDBDocumentClient,
): CatalogRepository => {
  if (config.dataAdapter === 'memory') {
    return new InMemoryCatalogRepository();
  }
  return new DynamoDbCatalogRepository(
    client ?? createDynamoDocumentClient(config),
    config.catalogTableName,
  );
};
