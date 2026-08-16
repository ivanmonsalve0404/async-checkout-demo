import type { DynamoDBDocumentClient } from '@aws-sdk/lib-dynamodb';
import { loadAppConfig } from '../configuration/app-config';
import { createCatalogRepository, createDynamoDocumentClient } from './catalog-repository.factory';
import { DynamoDbCatalogRepository } from './dynamodb-catalog.repository';
import { InMemoryCatalogRepository } from './in-memory-catalog.repository';

describe('catalog repository factory', () => {
  const memoryConfig = loadAppConfig({ APP_ENV: 'test' });
  const dynamoConfig = loadAppConfig({
    APP_ENV: 'test',
    DATA_ADAPTER: 'dynamodb',
    DYNAMODB_ENDPOINT: 'http://127.0.0.1:8000',
    RUNTIME_SECURITY_ROOT_KEY: Buffer.alloc(32, 7).toString('base64url'),
  });

  it('selects memory without using the injected DynamoDB client', () => {
    const send = jest.fn();
    const client = { send } as unknown as DynamoDBDocumentClient;
    expect(createCatalogRepository(memoryConfig, client)).toBeInstanceOf(InMemoryCatalogRepository);
    expect(send).not.toHaveBeenCalled();
  });

  it('reuses an injected client or creates the local document client when omitted', () => {
    const client = { send: jest.fn() } as unknown as DynamoDBDocumentClient;
    expect(createCatalogRepository(dynamoConfig, client)).toBeInstanceOf(DynamoDbCatalogRepository);
    expect(createCatalogRepository(dynamoConfig)).toBeInstanceOf(DynamoDbCatalogRepository);
    expect(createDynamoDocumentClient(dynamoConfig)).toBeDefined();
  });
});
