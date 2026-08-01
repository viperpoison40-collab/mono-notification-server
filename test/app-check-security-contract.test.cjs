const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const source = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

test("custom backend verifies Firebase App Check tokens", () => {
  assert.match(source, /require\("firebase-admin\/app-check"\)/);
  assert.match(source, /req\.headers\["x-firebase-appcheck"\]/);
  assert.match(source, /getAppCheck\(\)\.verifyToken\(token\)/);
  assert.match(source, /await verifyAppCheckRequest\(req\)/);
  assert.match(source, /Invalid Firebase App Check token/);
});

test("App Check uses a monitor-first rollout", () => {
  assert.match(source, /process\.env\.APP_CHECK_ENFORCEMENT/);
  assert.match(source, /return "monitor"/);
  assert.match(source, /mode !== "enforce"/);
  assert.match(source, /app-check monitor/);
  assert.match(source, /app-check verified/);
});

test("CORS allows the App Check header", () => {
  assert.match(source, /"X-Firebase-AppCheck"/);
});

test("App Check tokens are never written to logs", () => {
  const loggingCalls = source.match(/console\.(?:info|warn|error)\([\s\S]{0,350}?\);/g) || [];
  for (const call of loggingCalls) {
    assert.doesNotMatch(call, /appCheckToken|app-check-token|token\s*[,}]/i);
  }
});
