"use strict";

const http = require("node:http");

function handler(request, response) {
  const status = request.url === "/health" || request.url === "/ready" ? 200 : 404;
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify({ status: status === 200 ? "ok" : "not-found" }));
}

function start(port = Number(process.env.PORT || 3000)) {
  return http.createServer(handler).listen(port, "0.0.0.0");
}

if (require.main === module) {
  start();
}

module.exports = { handler, start };
