import { createServer } from 'node:http';
import { createApp } from './app';
import { ConfigError, loadConfigFromProcessEnv, type AppConfig } from './config/env';
import { createDatabase, describeDatabaseError } from './db/client';
import { createLifecycle } from './lifecycle';
import { createLogger } from './logging/logger';

const SHUTDOWN_TIMEOUT_MS = 10_000;

function loadConfigOrExit(): AppConfig {
  try {
    return loadConfigFromProcessEnv();
  } catch (error) {
    // The logger level is unknown without configuration, so write one fatal line directly.
    const message = error instanceof ConfigError ? error.message : 'Configuration could not be loaded';
    process.stderr.write(`${JSON.stringify({ time: new Date().toISOString(), level: 'fatal', msg: message })}\n`);
    process.exit(1);
  }
}

const config = loadConfigOrExit();
const logger = createLogger({ level: config.logLevel, base: { service: 'api' } });
const lifecycle = createLifecycle();
// Lazy: no connection is opened until the first query (readiness probe or request).
const database = createDatabase({ url: config.database.url, logger });
const { app, routes } = createApp({ config, logger, lifecycle, database });

const server = createServer(app);
// Slow-client limits (T-26). Nginx applies its own limits in front of these.
server.headersTimeout = 10_000;
server.requestTimeout = 30_000;
server.keepAliveTimeout = 5_000;
server.maxHeadersCount = 100;

server.listen(config.api.port, config.api.host, () => {
  lifecycle.markReady();
  logger.info('api listening', {
    host: config.api.host,
    port: config.api.port,
    environment: config.nodeEnv,
    routes: routes.length,
  });
});

function shutdown(signal: string): void {
  if (!lifecycle.isReady()) return;
  lifecycle.markShuttingDown();
  logger.info('shutdown started', { signal });
  server.close(() => {
    // Release pooled connections only after in-flight requests have finished.
    database.close().then(
      () => {
        logger.info('shutdown complete');
        process.exit(0);
      },
      (error: unknown) => {
        logger.error('database close failed', describeDatabaseError(error));
        process.exit(1);
      },
    );
  });
  server.closeIdleConnections();
  setTimeout(() => {
    logger.error('shutdown timed out, closing remaining connections');
    server.closeAllConnections();
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS).unref();
}

process.on('SIGTERM', () => {
  shutdown('SIGTERM');
});
process.on('SIGINT', () => {
  shutdown('SIGINT');
});
process.on('unhandledRejection', (reason) => {
  logger.fatal('unhandled promise rejection', { err: reason });
  process.exit(1);
});
process.on('uncaughtException', (err) => {
  logger.fatal('uncaught exception', { err });
  process.exit(1);
});
