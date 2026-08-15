import { NestFactory } from '@nestjs/core';
import type { INestApplication } from '@nestjs/common';
import helmet from 'helmet';
import { json, urlencoded } from 'express';
import { AppModule } from './app.module';
import { APP_CONFIG, type AppConfig } from './infrastructure/configuration/app-config';
import { ProblemFilter } from './interfaces/http/filters/problem.filter';

export const createApplication = async (): Promise<INestApplication> => {
  const application = await NestFactory.create(AppModule, { bodyParser: false, logger: false });
  const config = application.get<AppConfig>(APP_CONFIG);

  application.use(helmet());
  application.use(json({ limit: 16_384, strict: true }));
  application.use(urlencoded({ extended: false, limit: 16_384 }));
  application.enableCors({
    origin: config.allowedOrigin,
    methods: ['GET', 'HEAD', 'OPTIONS'],
    credentials: false,
    maxAge: 600,
  });
  application.useGlobalFilters(new ProblemFilter());
  application.enableShutdownHooks();
  return application;
};
