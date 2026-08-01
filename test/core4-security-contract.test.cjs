const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const server = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

function route(pathname, nextMarker) {
  const start = server.indexOf(`"${pathname}"`);
  assert.ok(start >= 0, `Missing ${pathname} endpoint`);
  const end = nextMarker ? server.indexOf(nextMarker, start) : -1;
  return server.slice(start, end > start ? end : start + 14000);
}

test("ad creation and payment proof require registered ImageKit ownership", () => {
  const create = route("/ads/create", '"/ads/payment-proof"');
  const proof = route("/ads/payment-proof", '"/ads/event"');

  for (const source of [create, proof]) {
    assert.match(source, /verifyUser/);
    assert.match(source, /secureAction\(/);
    assert.match(source, /requireOwnedAdAsset/);
    assert.match(source, /boundAdId/);
  }
  assert.match(server, /collection\("_mediaAssets"\)\.doc\(fileId\)/);
  assert.match(create, /ownerUid = req\.user\.uid/);
  assert.match(proof, /cleanText\(adSnap\.data\(\)\?\.ownerUid\) !== ownerUid/);
});

test("admin approval rechecks ad media ownership", () => {
  for (const action of ["approve_ad", "resume_ad", "approve_ad_payment"]) {
    const at = server.indexOf(`action === "${action}"`);
    assert.ok(at >= 0, `Missing ${action}`);
    assert.match(
      server.slice(at, at + 1200),
      /verifyAdMediaOwnership\(adId, adData\)/,
      `${action} must verify media ownership`,
    );
  }
});

test("post counters are mutated only through authenticated limited routes", () => {
  const routes = [
    ["/toggle-like", "toggle_like"],
    ["/add-comment", "add_comment"],
    ["/delete-comment", "delete_comment"],
    ["/toggle-comment-like", "toggle_comment_like"],
    ["/posts/toggle-save", "toggle_save"],
    ["/posts/share", "post_share"],
  ];

  for (const [pathname, action] of routes) {
    const source = route(pathname);
    assert.match(source.slice(0, 1200), /verifyUser/);
    assert.match(source.slice(0, 1200), new RegExp(`secureAction\\("${action}"`));
  }

  assert.match(route("/posts/toggle-save"), /savesCount/);
  assert.match(route("/posts/share"), /sharesCount/);
  assert.match(server, /engagementScore\(post/);
});

test("rate limits use a shared Firestore transaction store", () => {
  assert.match(server, /collection\("_serverRateLimits"\)/);
  assert.match(server, /db\.runTransaction/);
  assert.match(server, /const windowId = Math\.floor\(nowSeconds \/ windowSeconds\)/);
  assert.match(server, /error\.retryAfter = windowSeconds/);
  assert.doesNotMatch(server, /const\s+rateLimits\s*=\s*new Map/);
});

test("message and call pushes verify immutable server-side resources", () => {
  assert.match(server, /cleanText\(messageData\.fromUid\) !== senderUid/);
  assert.match(server, /cleanText\(messageData\.toUid\) !== toUid/);
  assert.match(server, /cleanText\(callData\.status\)\.toLowerCase\(\) !== "ringing"/);
  assert.match(server, /requireNoBlockBetween\(callerUid, receiverUid\)/);
  const notificationWriter = server.slice(
    server.indexOf("async function addNotificationDoc"),
    server.indexOf("async function sendInteractionPush"),
  );
  assert.match(
    notificationWriter,
    /requireNoBlockBetween\(cleanFromUid, cleanToUid\)/,
  );
});
