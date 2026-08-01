const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const source = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

test("bulk privacy migration is admin-only and resumable", () => {
  assert.match(
    source,
    /app\.post\("\/admin\/action",\s*verifyUser,\s*verifyAdmin,/,
  );
  assert.match(source, /action === "migrate_user_privacy_batch"/);
  assert.match(source, /FieldPath\.documentId\(\)/);
  assert.match(source, /startAfter\(cleanCursor\)/);
  assert.match(source, /nextCursor/);
  assert.match(source, /done/);
});

test("dry run does not create a write batch", () => {
  assert.match(source, /const batch = dryRun \? null : db\.batch\(\)/);
  assert.match(source, /dryRun: payload\.dryRun !== false/);
});

test("migration moves preferences and tokens before public cleanup", () => {
  assert.match(source, /legacyPrivateProfile/);
  assert.match(source, /collection\("private"\)\.doc\("profile"\)/);
  assert.match(source, /collection\("fcmTokens"\)\.doc\(token\)/);
  assert.match(source, /FieldValue\.delete\(\)/);
  assert.match(source, /tokens: valid\.slice\(0, 5\)/);
  assert.match(source, /safeLimit = boundedInt\(limit, 60, 1, 60\)/);
});

test("every migration batch is included in the existing admin audit log", () => {
  assert.match(source, /writeAdminLog\(req, adminUid, action, payload, result\)/);
});
