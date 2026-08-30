"use strict";

const assert = require("node:assert/strict");
const test = require("node:test");
const { start } = require("../src/server");

test("health and readiness endpoints respond", async (context) => {
  const server = start(0);
  await new Promise((resolve) => server.once("listening", resolve));
  context.after(() => server.close());
  const { port } = server.address();

  for (const path of ["/health", "/ready"]) {
    const response = await fetch(`http://127.0.0.1:${port}${path}`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok" });
  }
});
