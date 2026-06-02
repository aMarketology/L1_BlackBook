import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { snapshot, renderPrometheus } from "./metrics.js";
import { log } from "./logger.js";

const START_TIME = Date.now();

export function startServer(port: number): void {
  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = req.url ?? "/";

    if (url === "/health" || url === "/live") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          ok: true,
          uptime_seconds: Math.floor((Date.now() - START_TIME) / 1000),
          metrics: snapshot(),
        })
      );
      return;
    }

    if (url === "/metrics") {
      res.writeHead(200, { "Content-Type": "text/plain; version=0.0.4" });
      res.end(renderPrometheus());
      return;
    }

    res.writeHead(404);
    res.end("not found");
  });

  server.listen(port, () => {
    log.info("bridge-watcher HTTP server started", { port });
  });
}
