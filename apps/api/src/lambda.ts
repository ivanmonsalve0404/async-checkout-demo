import 'reflect-metadata';
import serverlessExpress from '@codegenie/serverless-express';
import type {
  APIGatewayProxyEventV2,
  APIGatewayProxyStructuredResultV2,
  Handler,
} from 'aws-lambda';
import { createApplication } from './bootstrap';

type ApiGatewayHandler = Handler<APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2>;

let cachedHandler: ApiGatewayHandler | undefined;

const initialize = async (): Promise<ApiGatewayHandler> => {
  const application = await createApplication();
  await application.init();
  const expressApplication: unknown = application.getHttpAdapter().getInstance();
  return serverlessExpress({
    app: expressApplication as Parameters<typeof serverlessExpress>[0]['app'],
  });
};

export const handler: ApiGatewayHandler = async (event, context, callback) => {
  cachedHandler ??= await initialize();
  const response: unknown = await cachedHandler(event, context, callback);
  return response as APIGatewayProxyStructuredResultV2;
};
