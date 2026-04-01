import app from "./app";
import { logger } from "./lib/logger";
import { cleanupExpiredCache, initDb } from "./lib/dbCache";

const rawPort = process.env["PORT"];

if (!rawPort) {
  throw new Error(
    "PORT environment variable is required but was not provided.",
  );
}

const port = Number(rawPort);

if (Number.isNaN(port) || port <= 0) {
  throw new Error(`Invalid PORT value: "${rawPort}"`);
}

app.listen(port, (err) => {
  if (err) {
    logger.error({ err }, "Error listening on port");
    process.exit(1);
  }

  logger.info({ port }, "Server listening");

  // Create tables if they don't exist (works with any fresh PostgreSQL DB)
  initDb().catch(() => {});
  // Purge expired DB cache rows every 6 hours
  cleanupExpiredCache().catch(() => {});
  setInterval(() => cleanupExpiredCache().catch(() => {}), 6 * 60 * 60 * 1000);
});
