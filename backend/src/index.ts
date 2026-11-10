import type { Server } from "node:http";
import { createApp } from "./api/app.js";
import { SentraDatabase } from "./database/database.js";

const port = Number(process.env.PORT ?? 3001);
const host = process.env.NODE_ENV === "production" ? "0.0.0.0" : "127.0.0.1";
const SHUTDOWN_TIMEOUT_MS = 10_000;

let hasShutdownStarted = false;
let databaseClosed = false;

function closeDatabaseOnce(database: SentraDatabase): void {
  if (databaseClosed) {
    return;
  }
  databaseClosed = true;

  try {
    database.close();
  } catch (error) {
    console.error("SENTRA shutdown warning: database close failed.", error);
  }
}

export function beginShutdown(server: Server, database: SentraDatabase, signal?: NodeJS.Signals): void {
  if (hasShutdownStarted) {
    return;
  }
  hasShutdownStarted = true;

  const signalText = signal ? ` (${signal})` : "";
  console.log(`SENTRA shutdown initiated${signalText}`);

  const timeout = setTimeout(() => {
    console.error(
      `SENTRA shutdown timed out after ${SHUTDOWN_TIMEOUT_MS}ms; forcing server close.`,
    );
    server.close(() => {
      closeDatabaseOnce(database);
      process.exitCode = 1;
    });
    server.closeAllConnections?.();
  }, SHUTDOWN_TIMEOUT_MS);

  server.close((error) => {
    clearTimeout(timeout);

    if (error) {
      console.error("SENTRA shutdown error: failed to close HTTP server cleanly.", error);
    }

    closeDatabaseOnce(database);
  });
}

export function startServer(): Server | undefined {
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("SENTRA startup failed: PORT must be an integer from 1 to 65535.");
    process.exitCode = 1;
    return undefined;
  }

  let database: SentraDatabase;
  try {
    database = new SentraDatabase();
  } catch (error) {
    console.error(
      "SENTRA startup failed: unable to initialize SQLite. Check DATABASE_PATH and filesystem permissions.",
      error,
    );
    process.exitCode = 1;
    return undefined;
  }

  const app = createApp(database);
  const server = app.listen(port, host, () => {
    console.log(`SENTRA backend listening on ${host}:${port}`);
  });

  const handleShutdown = (signal: NodeJS.Signals): void => {
    beginShutdown(server, database, signal);
  };

  process.once("SIGINT", handleShutdown);
  process.once("SIGTERM", handleShutdown);

  server.once("error", (error: NodeJS.ErrnoException) => {
    const code = error.code ? ` (${error.code})` : "";
    console.error(`SENTRA startup failed: unable to listen on ${host}:${port}${code}.`);
    closeDatabaseOnce(database);
    process.exitCode = 1;
  });

  server.once("close", () => {
    process.removeListener("SIGINT", handleShutdown);
    process.removeListener("SIGTERM", handleShutdown);
    if (process.exitCode === undefined) {
      process.exitCode = 0;
    }
  });

  return server;
}

startServer();
