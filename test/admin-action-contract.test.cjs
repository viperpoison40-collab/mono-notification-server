const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const serverSource = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

test("admin action endpoint requires authenticated admin middleware", () => {
  assert.match(
    serverSource,
    /app\.post\("\/admin\/action",\s*verifyUser,\s*verifyAdmin,/,
  );
});

test("all client admin mutations are handled by the backend", () => {
  const requiredActions = [
    "ban_user",
    "unban_user",
    "soft_delete_user",
    "restore_user",
    "disable_messaging",
    "delete_user_posts",
    "delete_user_stories",
    "delete_user_conversations",
    "update_report_status",
    "moderation_delete_post",
    "seed_ad_defaults",
    "save_ad_package",
    "save_ad_payment_account",
    "approve_ad",
    "reject_ad",
    "pause_ad",
    "resume_ad",
    "approve_ad_payment",
    "reject_ad_payment",
    "migrate_user_privacy_batch",
  ];

  requiredActions.forEach((action) => {
    assert.ok(serverSource.includes(`"${action}"`), `Missing ${action}`);
  });
});

test("production refuses a bundled service account fallback", () => {
  assert.match(serverSource, /process\.env\.VERCEL/);
  assert.match(
    serverSource,
    /Firebase Admin environment variables are required in production/,
  );
});
