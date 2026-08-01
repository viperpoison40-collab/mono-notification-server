const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const server = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);
const rules = fs.readFileSync(
  path.resolve(__dirname, "../../mono/firestore.rules"),
  "utf8",
);
const packageJson = require("../package.json");

test("security audit records are backend-only and append-only", () => {
  assert.match(server, /SECURITY_AUDIT_COLLECTION = "_securityAuditLogs"/);
  assert.match(server, /\.doc\(eventId\)\.create\(/);
  assert.match(
    rules,
    /match \/_securityAuditLogs\/\{eventId\}[\s\S]*?allow read, create, update, delete: if false/,
  );
});

test("security audit metadata excludes credentials and request bodies", () => {
  assert.match(
    server,
    /token\|secret\|password\|authorization\|cookie\|body\|email/i,
  );
  assert.match(server, /SECURITY_AUDIT_HMAC_KEY/);
  assert.match(server, /createHmac\("sha256", key\)/);
  assert.doesNotMatch(server, /metadata:\s*req\.body/);
});

test("important authorization events are persisted", () => {
  for (const eventType of [
    "rate_limit.exceeded",
    "authorization.admin_denied",
    "app_check.request_denied",
    "admin.delete_user_completely_started",
    "admin.delete_user_completely_finished",
  ]) {
    assert.ok(server.includes(eventType), `Missing ${eventType}`);
  }
});

test("dependency updates remain on Vercel-compatible major versions", () => {
  assert.equal(packageJson.dependencies["firebase-admin"], "14.2.0");
  assert.equal(packageJson.overrides.uuid, "11.1.1");
  assert.match(packageJson.dependencies.express, /^\^4\./);
  assert.match(packageJson.dependencies.dotenv, /^\^16\./);
});
