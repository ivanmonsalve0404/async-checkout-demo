import 'reflect-metadata';
import { createApplication } from './bootstrap';
import { APP_CONFIG, type AppConfig } from './infrastructure/configuration/app-config';

const main = async (): Promise<void> => {
  const application = await createApplication();
  const config = application.get<AppConfig>(APP_CONFIG);
  await application.listen(config.apiPort, '127.0.0.1');
};

void main();
