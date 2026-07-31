const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const source = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

test("Firebase Admin uses the supported modular API", () => {
  assert.match(source, /require\("firebase-admin\/app"\)/);
  assert.match(source, /require\("firebase-admin\/firestore"\)/);
  assert.match(source, /credential: cert\(serviceAccount\)/);
  assert.doesNotMatch(source, /admin\.credential/);
});

test("API applies security headers and an explicit CORS allowlist", () => {
  assert.match(source, /app\.use\(helmet\(\)\)/);
  assert.match(source, /process\.env\.ALLOWED_ORIGINS/);
  assert.doesNotMatch(source, /app\.use\(cors\(\)\)/);
  assert.match(source, /app\.disable\("x-powered-by"\)/);
});

test("sensitive user actions have authenticated rate limits", () => {
  for (const action of [
    "imagekit_auth",
    "send_message",
    "send_call",
    "send_notification",
    "ad_event",
    "delete_imagekit_file",
  ]) {
    assert.ok(source.includes(`secureAction("${action}"`), `Missing ${action}`);
  }
});

test("ad metrics are validated and written only by the backend", () => {
  const routeStart = source.indexOf('app.post(\n  "/ads/event"');
  const routeEnd = source.indexOf('app.post("/toggle-like"', routeStart);
  const route = source.slice(routeStart, routeEnd);

  assert.ok(routeStart >= 0, "Missing /ads/event endpoint");
  assert.match(route, /verifyUser/);
  assert.match(route, /secureAction\("ad_event"/);
  assert.match(route, /paymentStatus !== "paid"/);
  assert.match(route, /status !== "running"/);
  assert.match(route, /ownerUid === viewerUid/);
  assert.match(route, /impression-required-before-click/);
  assert.match(route, /tx\.create\(eventRef/);
  assert.match(route, /totalImpressions: nextImpressions/);
  assert.match(route, /totalClicks: nextClicks/);
});

test("message and call pushes verify server-side resources", () => {
  assert.match(source, /requireConversationParticipants/);
  assert.match(source, /db\.collection\("calls"\)\.doc\(callId\)\.get\(\)/);
  assert.match(source, /cleanText\(callData\.callerUid\) !== callerUid/);
});

test("generic notifications require an existing matching notification", () => {
  assert.match(source, /A valid notificationId is required/);
  assert.match(source, /cleanText\(notificationData\.fromUid\) !== fromUid/);
});

test("ImageKit delete verifies ownership or admin permission", () => {
  assert.match(source, /userOwnsImageKitFile\(actorUid, fileId\)/);
  assert.match(source, /File ownership could not be verified/);
});

test("ImageKit debug details are unavailable in production", () => {
  assert.match(
    source,
    /process\.env\.VERCEL \|\| process\.env\.NODE_ENV === "production"/,
  );
  assert.doesNotMatch(
    source.slice(
      source.indexOf('app.get("/debug/imagekit"'),
      source.indexOf("function getImageKitPrivateKey"),
    ),
    /privateKeyPreview/,
  );
});
