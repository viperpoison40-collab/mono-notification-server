const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const assert = require("node:assert/strict");

const server = fs.readFileSync(
  path.resolve(__dirname, "../server.js"),
  "utf8",
);

test("upload authorization requires declared metadata and a reservation", () => {
  assert.match(server, /app\.post\(\s*"\/imagekit-upload-auth"/);
  assert.match(server, /reserveMediaUpload/);
  assert.match(server, /validateMediaFolder/);
  assert.match(server, /MEDIA_DAILY_BYTES/);
  assert.match(server, /mediaExtensionAllowed/);
});

test("chat media folders require conversation membership", () => {
  assert.match(server, /collection\("conversations"\)\.doc\(chatMatch\[1\]\)/);
  assert.match(server, /participants\.includes\(uid\)/);
});

test("completed uploads are verified against ImageKit and registered", () => {
  assert.match(server, /"\/imagekit-upload-complete"/);
  assert.match(server, /getImageKitFileDetails\(fileId\)/);
  assert.match(server, /actualPath !== expectedPath/);
  assert.match(server, /collection\("_mediaAssets"\)\.doc\(fileId\)/);
});

test("failed uploads can release quota and delete matched remote files", () => {
  assert.match(server, /"\/imagekit-upload-cancel"/);
  assert.match(server, /releaseMediaReservation/);
  assert.match(server, /FieldValue\.increment\(-1\)/);
});

test("ownership registry is checked before legacy Firestore lookup", () => {
  const registryAt = server.indexOf('collection("_mediaAssets")');
  const legacyAt = server.indexOf('["posts", "mediaFileId"]');
  assert.ok(registryAt > -1 && legacyAt > registryAt);
});
