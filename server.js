require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const { cert, initializeApp } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getAppCheck } = require("firebase-admin/app-check");
const {
  FieldPath,
  FieldValue,
  Timestamp,
  getFirestore,
} = require("firebase-admin/firestore");
const { getMessaging } = require("firebase-admin/messaging");
const fs = require("fs");
const { createHmac, randomBytes, randomUUID } = require("crypto");

const app = express();

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(helmet());
const allowedOrigins = new Set(
  String(process.env.ALLOWED_ORIGINS || "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean),
);
app.use(
  cors({
    origin(origin, callback) {
      if (!origin || allowedOrigins.has(origin)) return callback(null, true);
      const error = new Error("Origin is not allowed");
      error.statusCode = 403;
      return callback(error);
    },
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: [
      "Authorization",
      "Content-Type",
      "X-Request-ID",
      "X-Firebase-AppCheck",
    ],
    maxAge: 86400,
  }),
);
app.use((req, res, next) => {
  const suppliedId = String(req.headers["x-request-id"] || "").trim();
  req.requestId = /^[A-Za-z0-9._-]{8,100}$/.test(suppliedId)
    ? suppliedId
    : randomUUID();
  res.setHeader("X-Request-ID", req.requestId);
  res.setHeader("Cache-Control", "no-store");
  next();
});
app.use(express.json({ limit: "1mb" }));

const localServiceAccountPath = "./serviceAccountKey.json";
const hasEnvironmentCredential =
  cleanText(process.env.FIREBASE_PROJECT_ID) &&
  cleanText(process.env.FIREBASE_CLIENT_EMAIL) &&
  cleanText(process.env.FIREBASE_PRIVATE_KEY);

if (
  !hasEnvironmentCredential &&
  (process.env.VERCEL || process.env.NODE_ENV === "production")
) {
  throw new Error(
    "Firebase Admin environment variables are required in production.",
  );
}

const serviceAccount = hasEnvironmentCredential
  ? {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }
  : fs.existsSync(localServiceAccountPath)
    ? require(localServiceAccountPath)
    : null;

if (!serviceAccount) {
  throw new Error("Firebase Admin credentials are not configured.");
}

initializeApp({
  credential: cert(serviceAccount),
});

const db = getFirestore();
const privacyMigrationChecked = new Set();

function cleanText(value) {
  return String(value ?? "").trim();
}

function shortText(value, max = 120) {
  const text = cleanText(value);
  if (!text) return "";
  return text.length > max ? `${text.substring(0, max)}...` : text;
}

function safeData(data = {}) {
  const output = {};
  Object.entries(data).forEach(([key, value]) => {
    const cleanKey = cleanText(key);
    const cleanValue = cleanText(value);
    if (cleanKey && cleanValue) output[cleanKey] = cleanValue;
  });
  return output;
}

function uniqueCleanStrings(values) {
  const out = [];
  const seen = new Set();

  values.forEach((value) => {
    const clean = cleanText(value);
    if (!clean || seen.has(clean)) return;
    seen.add(clean);
    out.push(clean);
  });

  return out;
}

const LEGACY_PRIVATE_USER_FIELDS = [
  "email",
  "emailLower",
  "phone",
  "phoneNumber",
  "fcmToken",
  "pushToken",
  "notificationToken",
  "apnsToken",
  "lastFcmToken",
  "lastFcmTokenUpdatedAt",
  "deviceToken",
  "deviceTokens",
  "country",
  "city",
  "gender",
  "adInterests",
];

function legacyUserTokenCandidates(data = {}) {
  const values = [
    data.lastFcmToken,
    data.fcmToken,
    data.pushToken,
    data.notificationToken,
    data.apnsToken,
    data.deviceToken,
  ];

  if (Array.isArray(data.deviceTokens)) {
    values.push(...data.deviceTokens);
  } else if (data.deviceTokens && typeof data.deviceTokens === "object") {
    values.push(...Object.values(data.deviceTokens));
  }

  const unique = uniqueCleanStrings(values);
  const valid = unique.filter(
    (token) =>
      token.length >= 6 && token.length <= 4096 && !token.includes("/"),
  );

  return {
    tokens: valid.slice(0, 5),
    invalidTokenCount:
      unique.length - valid.length + Math.max(0, valid.length - 5),
  };
}

function legacyPrivateProfile(data = {}) {
  const profile = {};

  if (Object.prototype.hasOwnProperty.call(data, "country")) {
    profile.country = shortText(data.country, 80).toLowerCase();
  }
  if (Object.prototype.hasOwnProperty.call(data, "city")) {
    profile.city = shortText(data.city, 80).toLowerCase();
  }
  if (Object.prototype.hasOwnProperty.call(data, "gender")) {
    const gender = cleanText(data.gender).toLowerCase();
    profile.gender = ["male", "female"].includes(gender) ? gender : "all";
  }
  if (Array.isArray(data.adInterests)) {
    profile.adInterests = uniqueCleanStrings(data.adInterests).slice(0, 12);
  }

  return profile;
}

function legacyUserPrivacyPlan(data = {}) {
  const existingFields = LEGACY_PRIVATE_USER_FIELDS.filter((field) =>
    Object.prototype.hasOwnProperty.call(data, field),
  );
  const tokenResult = legacyUserTokenCandidates(data);

  return {
    existingFields,
    privateProfile: legacyPrivateProfile(data),
    tokens: tokenResult.tokens,
    invalidTokenCount: tokenResult.invalidTokenCount,
  };
}

function addUserPrivacyMigrationWrites(batch, userRef, plan) {
  if (Object.keys(plan.privateProfile).length > 0) {
    batch.set(
      userRef.collection("private").doc("profile"),
      {
        ...plan.privateProfile,
        schemaVersion: 1,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  }

  plan.tokens.forEach((token) => {
    batch.set(
      userRef.collection("fcmTokens").doc(token),
      {
        token,
        platform: "legacy",
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  });

  const publicCleanup = {};
  plan.existingFields.forEach((field) => {
    publicCleanup[field] = FieldValue.delete();
  });
  batch.update(userRef, publicCleanup);
}

async function migrateLegacyPrivateUserData(uid) {
  const cleanUid = cleanText(uid);
  if (!cleanUid || privacyMigrationChecked.has(cleanUid)) return;

  const userRef = db.collection("users").doc(cleanUid);
  const snap = await userRef.get();
  if (!snap.exists) {
    privacyMigrationChecked.add(cleanUid);
    return;
  }

  const plan = legacyUserPrivacyPlan(snap.data() || {});
  if (plan.existingFields.length === 0) {
    privacyMigrationChecked.add(cleanUid);
    return;
  }

  const batch = db.batch();
  addUserPrivacyMigrationWrites(batch, userRef, plan);
  await batch.commit();
  privacyMigrationChecked.add(cleanUid);
}

async function runUserPrivacyMigrationBatch({
  adminUid,
  cursor = "",
  dryRun = true,
  limit = 60,
  requestId = "",
}) {
  const cleanCursor = cleanText(cursor);
  const safeLimit = boundedInt(limit, 60, 1, 60);

  if (cleanCursor && !isSafeDocumentId(cleanCursor)) {
    const error = new Error("Invalid migration cursor");
    error.statusCode = 400;
    throw error;
  }

  let query = db
    .collection("users")
    .orderBy(FieldPath.documentId())
    .limit(safeLimit);
  if (cleanCursor) query = query.startAfter(cleanCursor);

  const snap = await query.get();
  const batch = dryRun ? null : db.batch();
  let needsMigration = 0;
  let migrated = 0;
  let invalidTokenCount = 0;
  const migratedIds = [];

  snap.docs.forEach((userDoc) => {
    const plan = legacyUserPrivacyPlan(userDoc.data() || {});
    if (plan.existingFields.length === 0) return;

    needsMigration += 1;
    invalidTokenCount += plan.invalidTokenCount;

    if (batch) {
      addUserPrivacyMigrationWrites(batch, userDoc.ref, plan);
      migrated += 1;
      migratedIds.push(userDoc.id);
    }
  });

  const nextCursor = snap.empty ? "" : snap.docs[snap.docs.length - 1].id;
  const done = snap.size < safeLimit;

  if (batch && migrated > 0) {
    await batch.commit();
    migratedIds.forEach((uid) => privacyMigrationChecked.add(uid));
  }

  return {
    dryRun: Boolean(dryRun),
    scanned: snap.size,
    needsMigration,
    migrated,
    invalidTokenCount,
    nextCursor,
    done,
    requestId: cleanText(requestId),
    adminUid: cleanText(adminUid),
  };
}

function isSafeDocumentId(value) {
  const text = cleanText(value);
  return Boolean(text) && text.length <= 256 && !text.includes("/");
}

function userIsDisabled(data = {}) {
  const status = cleanText(data.status).toLowerCase();
  return (
    data.banned === true ||
    data.isBanned === true ||
    data.deleted === true ||
    data.isDeleted === true ||
    ["banned", "deleted", "disabled"].includes(status)
  );
}

async function requireActiveUser(uid, { messaging = false } = {}) {
  const snap = await db.collection("users").doc(cleanText(uid)).get();
  if (!snap.exists) {
    const error = new Error("user-not-found");
    error.statusCode = 403;
    throw error;
  }

  const data = snap.data() || {};
  if (userIsDisabled(data) || (messaging && data.canMessage === false)) {
    const error = new Error("user-disabled");
    error.statusCode = 403;
    throw error;
  }
  return data;
}

async function requireConversationParticipants(convoId, firstUid, secondUid) {
  if (!isSafeDocumentId(convoId)) {
    const error = new Error("invalid-conversation");
    error.statusCode = 400;
    throw error;
  }
  const snap = await db.collection("conversations").doc(convoId).get();
  const participants = snap.exists
    ? uniqueCleanStrings(snap.data()?.participants || [])
    : [];
  if (
    !snap.exists ||
    !participants.includes(firstUid) ||
    !participants.includes(secondUid)
  ) {
    const error = new Error("conversation-permission-denied");
    error.statusCode = 403;
    throw error;
  }
}

async function requireNoBlockBetween(firstUid, secondUid) {
  const first = cleanText(firstUid);
  const second = cleanText(secondUid);
  if (!first || !second || first === second) {
    const error = new Error("invalid-block-check");
    error.statusCode = 400;
    throw error;
  }

  const refs = [
    db.collection("users").doc(first).collection("blocked").doc(second),
    db.collection("users").doc(second).collection("blocked").doc(first),
    db.collection("users").doc(first).collection("blockedUsers").doc(second),
    db.collection("users").doc(second).collection("blockedUsers").doc(first),
  ];
  const snapshots = await db.getAll(...refs);
  if (snapshots.some((snap) => snap.exists)) {
    const error = new Error("users-blocked");
    error.statusCode = 403;
    throw error;
  }
}

async function enforceUserRateLimit(uid, action, limit, windowSeconds) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const windowId = Math.floor(nowSeconds / windowSeconds);
  const key = `${cleanText(uid)}_${cleanText(action)}_${windowId}`.replace(
    /[^A-Za-z0-9_-]/g,
    "_",
  );
  const ref = db.collection("_serverRateLimits").doc(key);

  await db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const count = snap.exists ? Number(snap.data()?.count || 0) : 0;
    if (count >= limit) {
      const error = new Error("rate-limit-exceeded");
      error.statusCode = 429;
      error.retryAfter = windowSeconds - (nowSeconds % windowSeconds);
      throw error;
    }
    tx.set(
      ref,
      {
        uid: cleanText(uid),
        action: cleanText(action),
        count: count + 1,
        expiresAt: Timestamp.fromMillis(
          (nowSeconds + windowSeconds * 2) * 1000,
        ),
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
  });
}

function secureAction(
  action,
  limit,
  windowSeconds = 60,
  { messaging = true } = {},
) {
  return async (req, res, next) => {
    try {
      await requireActiveUser(req.user.uid, { messaging });
      await enforceUserRateLimit(
        req.user.uid,
        action,
        limit,
        windowSeconds,
      );
      return next();
    } catch (error) {
      if (error.retryAfter) res.setHeader("Retry-After", error.retryAfter);
      return res.status(error.statusCode || 403).json({
        ok: false,
        error:
          error.message === "rate-limit-exceeded"
            ? "Too many requests"
            : "Account is not allowed to perform this action",
        requestId: req.requestId,
      });
    }
  };
}

function appCheckEnforcementMode() {
  const mode = cleanText(process.env.APP_CHECK_ENFORCEMENT).toLowerCase();
  if (mode === "off" || mode === "enforce") return mode;
  return "monitor";
}

function logAppCheckMonitorFailure(req, reason) {
  console.warn("app-check monitor", {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    reason,
  });
}

async function verifyAppCheckRequest(req) {
  const mode = appCheckEnforcementMode();
  req.appCheck = {
    mode,
    valid: false,
    appId: "",
    reason: mode === "off" ? "disabled" : "missing",
  };

  if (mode === "off") {
    return { allowed: true, valid: false, reason: "disabled" };
  }

  const token = cleanText(req.headers["x-firebase-appcheck"]);
  if (!token) {
    if (mode === "monitor") logAppCheckMonitorFailure(req, "missing");
    return {
      allowed: mode !== "enforce",
      valid: false,
      reason: "missing",
    };
  }

  try {
    const decoded = await getAppCheck().verifyToken(token);
    const appId = cleanText(decoded.appId);
    req.appCheck = {
      mode,
      valid: true,
      appId,
      reason: "valid",
    };
    if (mode === "monitor") {
      console.info("app-check verified", {
        requestId: req.requestId,
        method: req.method,
        path: req.path,
        appId,
      });
    }
    return { allowed: true, valid: true, appId, reason: "valid" };
  } catch (_) {
    req.appCheck.reason = "invalid";
    if (mode === "monitor") logAppCheckMonitorFailure(req, "invalid");
    return {
      allowed: mode !== "enforce",
      valid: false,
      reason: "invalid",
    };
  }
}

async function verifyUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.substring("Bearer ".length)
      : "";

    if (!token) {
      return res.status(401).json({
        ok: false,
        error: "Missing Firebase ID token",
      });
    }

    const decoded = await getAuth().verifyIdToken(token);
    const appCheckResult = await verifyAppCheckRequest(req);
    if (!appCheckResult.allowed) {
      return res.status(401).json({
        ok: false,
        error: "Invalid Firebase App Check token",
        requestId: req.requestId,
      });
    }
    req.user = decoded;
    await migrateLegacyPrivateUserData(decoded.uid).catch((error) => {
      console.warn("User privacy migration failed", decoded.uid, error.message);
    });
    return next();
  } catch (_) {
    return res.status(401).json({
      ok: false,
      error: "Invalid Firebase ID token",
    });
  }
}

async function isAdminUser(uid, email = "") {
  const cleanUid = cleanText(uid);
  const cleanEmail = cleanText(email).toLowerCase();

  const ownerEmails = uniqueCleanStrings([
    "viper.poison40@gmail.com",
    ...(cleanText(process.env.ADMIN_EMAILS)
      ? process.env.ADMIN_EMAILS.split(",")
      : []),
  ]).map((e) => e.toLowerCase());

  if (cleanEmail && ownerEmails.includes(cleanEmail)) return true;
  if (!cleanUid) return false;

  try {
    const snap = await db.collection("users").doc(cleanUid).get();
    const data = snap.data() || {};
    const role = cleanText(data.role).toLowerCase();
    const roles = Array.isArray(data.roles)
      ? data.roles.map((value) => cleanText(value).toLowerCase())
      : [];

    return (
      data.isAdmin === true ||
      data.admin === true ||
      ["admin", "owner", "moderator"].includes(role) ||
      roles.some((value) =>
        ["admin", "owner", "moderator"].includes(value),
      )
    );
  } catch (error) {
    console.warn("Failed to check admin user", cleanUid, error.message);
    return false;
  }
}

async function verifyAdmin(req, res, next) {
  try {
    const ok = await isAdminUser(req.user?.uid, req.user?.email);
    if (!ok) {
      return res.status(403).json({
        ok: false,
        error: "Admin permission required",
      });
    }

    return next();
  } catch (_) {
    return res.status(403).json({
      ok: false,
      error: "Admin permission required",
    });
  }
}

async function getUserTitle(uid) {
  if (!uid) return "MONO";

  try {
    const snap = await db.collection("users").doc(uid).get();
    const data = snap.data() || {};

    const displayName = cleanText(data.displayName);
    if (displayName) return displayName;

    const username = cleanText(data.username);
    if (username) return `@${username}`;
  } catch (error) {
    console.warn("Failed to read user title", uid, error.message);
  }

  return "MONO";
}

async function getPublicUserData(uid) {
  const snap = await db.collection("users").doc(uid).get();
  const data = snap.data() || {};

  return {
    username: cleanText(data.username) || cleanText(data.displayName) || "user",
    avatarUrl: cleanText(data.avatarUrl),
  };
}

async function getUserTokens(uid) {
  const snap = await db
    .collection("users")
    .doc(uid)
    .collection("fcmTokens")
    .limit(30)
    .get();

  const tokens = new Set();

  snap.docs.forEach((doc) => {
    const data = doc.data() || {};
    const token = cleanText(data.token || doc.id);
    if (token) tokens.add(token);
  });

  return Array.from(tokens);
}


const DEFAULT_NOTIFICATION_PREFERENCES = {
  enabled: true,
  messages: true,
  calls: true,
  likes: true,
  comments: true,
  commentLikes: true,
  follows: true,
  stories: true,
  general: true,
};

function notificationPreferenceKey(type = "") {
  const cleanType = cleanText(type).toLowerCase();

  if (cleanType === "message" || cleanType === "messages") return "messages";
  if (
    cleanType === "call" ||
    cleanType === "calls" ||
    cleanType === "incoming_call" ||
    cleanType === "missed_call"
  ) {
    return "calls";
  }
  if (cleanType === "like" || cleanType === "likes") return "likes";
  if (cleanType === "comment" || cleanType === "comments") return "comments";
  if (
    cleanType === "comment_like" ||
    cleanType === "comment_likes" ||
    cleanType === "commentlikes" ||
    cleanType === "commentLikes"
  ) {
    return "commentLikes";
  }
  if (
    cleanType === "follow" ||
    cleanType === "new_follow" ||
    cleanType === "follows"
  ) {
    return "follows";
  }
  if (cleanType === "story" || cleanType === "stories") return "stories";

  return "general";
}

function notificationTypeFromData(data = {}) {
  const notificationType = cleanText(data.notificationType).toLowerCase();
  if (notificationType) return notificationType;

  const type = cleanText(data.type).toLowerCase();
  if (type) return type;

  return "general";
}

async function getNotificationPreferences(uid) {
  const cleanUid = cleanText(uid);
  if (!cleanUid) return { ...DEFAULT_NOTIFICATION_PREFERENCES };

  try {
    const snap = await db
      .collection("users")
      .doc(cleanUid)
      .collection("settings")
      .doc("notificationPreferences")
      .get();

    if (!snap.exists) {
      return { ...DEFAULT_NOTIFICATION_PREFERENCES };
    }

    const data = snap.data() || {};

    return {
      ...DEFAULT_NOTIFICATION_PREFERENCES,
      ...data,
    };
  } catch (error) {
    console.warn("Failed to read notification preferences", {
      uid: cleanUid,
      error: error.message,
    });

    return { ...DEFAULT_NOTIFICATION_PREFERENCES };
  }
}

async function isNotificationTypeEnabled(uid, type) {
  const cleanUid = cleanText(uid);
  if (!cleanUid) return false;

  const prefs = await getNotificationPreferences(cleanUid);
  const key = notificationPreferenceKey(type);

  if (prefs.enabled === false) return false;
  if (prefs[key] === false) return false;

  return true;
}

async function skipNotificationResult({ uid, type, reason = "notification-disabled" }) {
  return {
    ok: true,
    sent: 0,
    failed: 0,
    skipped: true,
    reason,
    uid: cleanText(uid),
    notificationType: notificationPreferenceKey(type),
  };
}


async function deleteBadTokens(uid, badTokens) {
  if (!uid || badTokens.length === 0) return;

  const batch = db.batch();

  badTokens.forEach((token) => {
    batch.delete(
      db.collection("users").doc(uid).collection("fcmTokens").doc(token),
    );
  });

  await batch.commit();
}

function collectBadTokens(response, tokens, uid) {
  const badTokens = [];

  response.responses.forEach((result, index) => {
    if (result.success) return;

    const code = result.error?.code || "";

    if (
      code.includes("registration-token-not-registered") ||
      code.includes("invalid-registration-token") ||
      code.includes("invalid-argument")
    ) {
      badTokens.push(tokens[index]);
    }

    console.warn("FCM send failed", {
      uid,
      index,
      code,
      message: result.error?.message,
    });
  });

  return badTokens;
}

async function sendPushToUser({
  uid,
  title,
  body,
  data = {},
  collapseKey = "mono_general",
  tag = "mono_general",
}) {
  const notificationType = notificationTypeFromData(data);
  const allowed = await isNotificationTypeEnabled(uid, notificationType);

  if (!allowed) {
    return skipNotificationResult({
      uid,
      type: notificationType,
    });
  }

  const tokens = await getUserTokens(uid);

  if (tokens.length === 0) {
    return {
      ok: true,
      sent: 0,
      failed: 0,
      message: "No FCM tokens found for this user",
    };
  }

  const cleanData = safeData({ ...data, title, body });

  const response = await getMessaging().sendEachForMulticast({
    tokens,
    notification: { title, body },
    data: cleanData,
    android: {
      priority: "high",
      collapseKey,
      notification: {
        channelId: "mono_default_channel",
        sound: "default",
        priority: "high",
        defaultSound: true,
        defaultVibrateTimings: true,
        tag,
        clickAction: "FLUTTER_NOTIFICATION_CLICK",
      },
    },
  });

  const badTokens = collectBadTokens(response, tokens, uid);
  await deleteBadTokens(uid, badTokens);

  return {
    ok: true,
    sent: response.successCount,
    failed: response.failureCount,
    deletedBadTokens: badTokens.length,
  };
}

async function sendDataOnlyPushToUser({
  uid,
  data = {},
  collapseKey = "mono_data",
}) {
  const notificationType = notificationTypeFromData(data);
  const allowed = await isNotificationTypeEnabled(uid, notificationType);

  if (!allowed) {
    return skipNotificationResult({
      uid,
      type: notificationType,
    });
  }

  const tokens = await getUserTokens(uid);

  if (tokens.length === 0) {
    return {
      ok: true,
      sent: 0,
      failed: 0,
      message: "No FCM tokens found for this user",
    };
  }

  const response = await getMessaging().sendEachForMulticast({
    tokens,
    data: safeData(data),
    android: {
      priority: "high",
      collapseKey,
      ttl: 45000,
    },
    apns: {
      headers: { "apns-priority": "10" },
      payload: { aps: { contentAvailable: true } },
    },
  });

  const badTokens = collectBadTokens(response, tokens, uid);
  await deleteBadTokens(uid, badTokens);

  return {
    ok: true,
    sent: response.successCount,
    failed: response.failureCount,
    deletedBadTokens: badTokens.length,
  };
}

function trendScore(likesCount, commentsCount) {
  return Number(likesCount || 0) + Number(commentsCount || 0) * 2;
}

function engagementScore(data = {}, overrides = {}) {
  const value = (key) => Math.max(
    0,
    Number(Object.prototype.hasOwnProperty.call(overrides, key)
      ? overrides[key]
      : data[key] || 0),
  );
  return Number((
    value("likesCount") +
    value("commentsCount") * 2 +
    value("savesCount") * 3 +
    value("sharesCount") * 4 +
    value("viewsCount") * 0.2
  ).toFixed(2));
}

function likeNotificationId(postId, actorUid) {
  return `like_${cleanText(postId)}_${cleanText(actorUid)}`;
}

function commentNotificationId(postId, commentId) {
  return `comment_${cleanText(postId)}_${cleanText(commentId)}`;
}

function commentLikeNotificationId(postId, commentId, actorUid) {
  return `comment_like_${cleanText(postId)}_${cleanText(commentId)}_${cleanText(actorUid)}`;
}

function followNotificationId(followerUid) {
  return `follow_${cleanText(followerUid)}`;
}

async function addNotificationDoc({
  toUid,
  type,
  fromUid,
  text,
  postId = "",
  commentId = "",
  notificationId = "",
}) {
  const cleanToUid = cleanText(toUid);
  const cleanType = cleanText(type).toLowerCase();
  const cleanFromUid = cleanText(fromUid);
  const cleanPostId = cleanText(postId);
  const cleanCommentId = cleanText(commentId);
  const cleanNotificationId = cleanText(notificationId);

  if (!cleanToUid || !cleanType || !cleanFromUid) return;
  if (cleanToUid === cleanFromUid) return;

  try {
    await requireNoBlockBetween(cleanFromUid, cleanToUid);
  } catch (error) {
    if (error.message === "users-blocked") return;
    throw error;
  }

  const allowed = await isNotificationTypeEnabled(cleanToUid, cleanType);
  if (!allowed) return;

  const ref = cleanNotificationId
    ? db
        .collection("users")
        .doc(cleanToUid)
        .collection("notifications")
        .doc(cleanNotificationId)
    : db.collection("users").doc(cleanToUid).collection("notifications").doc();

  await ref.set(
    {
      id: ref.id,
      type: cleanType,
      fromUid: cleanFromUid,
      postId: cleanPostId || null,
      commentId: cleanCommentId || null,
      text: cleanText(text),
      createdAt: FieldValue.serverTimestamp(),
      seen: false,
    },
    { merge: true },
  );
}


async function sendInteractionPush({
  toUid,
  type,
  fromUid,
  postId = "",
  commentId = "",
  notificationId = "",
  text = "",
}) {
  const cleanToUid = cleanText(toUid);
  const cleanType = cleanText(type).toLowerCase();
  const cleanFromUid = cleanText(fromUid);
  const cleanPostId = cleanText(postId);
  const cleanCommentId = cleanText(commentId);
  const cleanNotificationId = cleanText(notificationId);

  if (!cleanToUid || !cleanType || !cleanFromUid) return null;
  if (cleanToUid === cleanFromUid) return null;

  try {
    await requireNoBlockBetween(cleanFromUid, cleanToUid);
  } catch (error) {
    if (error.message === "users-blocked") return null;
    throw error;
  }

  const fromName = await getUserTitle(cleanFromUid);

  let title = "إشعار جديد";
  let body = cleanText(text) || "لديك إشعار جديد";
  let collapseKey = "mono_general";
  let tag = cleanNotificationId ? `notification_${cleanNotificationId}` : "mono_general";

  if (cleanType === "like") {
    title = "إعجاب جديد";
    body = `${fromName} أعجب بمنشورك`;
    collapseKey = cleanPostId ? `post_${cleanPostId}` : "mono_like";
    tag = cleanNotificationId || (cleanPostId ? `like_${cleanPostId}` : "mono_like");
  } else if (cleanType === "comment") {
    title = "تعليق جديد";
    body = cleanText(text)
      ? `${fromName}: ${shortText(text, 90)}`
      : `${fromName} علّق على منشورك`;
    collapseKey = cleanPostId ? `post_${cleanPostId}` : "mono_comment";
    tag = cleanNotificationId || (cleanPostId ? `comment_${cleanPostId}` : "mono_comment");
  } else if (cleanType === "comment_like") {
    title = "إعجاب بتعليقك";
    body = `${fromName} أعجب بتعليقك`;
    collapseKey = cleanPostId ? `post_${cleanPostId}` : "mono_comment_like";
    tag = cleanNotificationId || (cleanCommentId ? `comment_like_${cleanCommentId}` : "mono_comment_like");
  } else if (cleanType === "follow" || cleanType === "new_follow") {
    title = "متابع جديد";
    body = `${fromName} بدأ بمتابعتك`;
    collapseKey = `user_${cleanFromUid}`;
    tag = cleanNotificationId || `follow_${cleanFromUid}`;
  }

  try {
    return await sendPushToUser({
      uid: cleanToUid,
      title,
      body,
      collapseKey,
      tag,
      data: {
        type: cleanType,
        notificationType: cleanType,
        notificationId: cleanNotificationId,
        postId: cleanPostId,
        commentId: cleanCommentId,
        fromUid: cleanFromUid,
        toUid: cleanToUid,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });
  } catch (error) {
    console.warn("interaction push failed", {
      toUid: cleanToUid,
      type: cleanType,
      fromUid: cleanFromUid,
      error: error.message,
    });
    return null;
  }
}

async function hasActiveCallBetweenUsers({ callerUid, receiverUid, callId = "" }) {
  const cleanCallerUid = cleanText(callerUid);
  const cleanReceiverUid = cleanText(receiverUid);
  const cleanCallId = cleanText(callId);

  if (!cleanCallerUid || !cleanReceiverUid) return false;

  const snap = await db
    .collection("calls")
    .where("callerUid", "==", cleanCallerUid)
    .where("receiverUid", "==", cleanReceiverUid)
    .limit(10)
    .get();

  const activeStatuses = new Set(["ringing", "accepted", "connecting"]);

  for (const doc of snap.docs) {
    if (cleanCallId && doc.id === cleanCallId) continue;

    const data = doc.data() || {};
    const status = cleanText(data.status).toLowerCase();

    if (!activeStatuses.has(status)) continue;

    const createdAt = data.createdAt;
    if (createdAt && typeof createdAt.toDate === "function") {
      const ageMs = Date.now() - createdAt.toDate().getTime();
      if (ageMs > 90 * 1000 && status === "ringing") continue;
    }

    return true;
  }

  return false;
}

async function deleteNotificationDoc({ toUid, notificationId }) {
  const cleanToUid = cleanText(toUid);
  const cleanNotificationId = cleanText(notificationId);

  if (!cleanToUid || !cleanNotificationId) return;

  await db
    .collection("users")
    .doc(cleanToUid)
    .collection("notifications")
    .doc(cleanNotificationId)
    .delete()
    .catch(() => {});
}

function imageKitFileIdsFromPost(postData = {}) {
  return uniqueCleanStrings([
    postData.mediaFileId,
    postData.thumbnailFileId,
    postData.imageKitFileId,
    postData.imageKitThumbnailFileId,
    postData.mediaImageKitFileId,
    postData.thumbnailImageKitFileId,
  ]);
}

function imageKitFileIdsFromStory(storyData = {}) {
  return uniqueCleanStrings([
    storyData.mediaFileId,
    storyData.imageKitFileId,
    storyData.mediaImageKitFileId,
    storyData.thumbnailFileId,
    storyData.thumbnailImageKitFileId,
  ]);
}

async function userOwnsImageKitFile(uid, fileId) {
  const cleanUid = cleanText(uid);
  const cleanFileId = cleanText(fileId);
  const assetSnap = await db.collection("_mediaAssets").doc(cleanFileId).get();
  if (
    assetSnap.exists &&
    cleanText(assetSnap.data()?.ownerUid) === cleanUid &&
    cleanText(assetSnap.data()?.status) !== "deleted"
  ) {
    return true;
  }
  const candidates = [
    ["posts", "mediaFileId"],
    ["posts", "thumbnailFileId"],
    ["posts", "imageKitFileId"],
    ["posts", "imageKitThumbnailFileId"],
    ["posts", "mediaImageKitFileId"],
    ["posts", "thumbnailImageKitFileId"],
    ["stories", "mediaFileId"],
    ["stories", "thumbnailFileId"],
    ["stories", "imageKitFileId"],
    ["stories", "mediaImageKitFileId"],
    ["stories", "thumbnailImageKitFileId"],
  ];

  for (const [collection, field] of candidates) {
    const snap = await db
      .collection(collection)
      .where(field, "==", cleanFileId)
      .limit(3)
      .get();
    if (
      snap.docs.some((doc) => {
        const data = doc.data() || {};
        return cleanText(data.userId || data.uid || data.ownerUid) === cleanUid;
      })
    ) {
      return true;
    }
  }
  return false;
}

async function deleteImageKitFile(fileId) {
  const cleanFileId = cleanText(fileId);
  const privateKey = cleanText(process.env.IMAGEKIT_PRIVATE_KEY);

  if (!cleanFileId) {
    return {
      ok: true,
      skipped: true,
      reason: "empty-file-id",
    };
  }

  if (!privateKey) {
    console.warn(
      "IMAGEKIT_PRIVATE_KEY is not configured; skipping media delete",
      cleanFileId,
    );

    return {
      ok: true,
      skipped: true,
      reason: "missing-imagekit-private-key",
    };
  }

  const response = await fetch(
    `https://api.imagekit.io/v1/files/${encodeURIComponent(cleanFileId)}`,
    {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${Buffer.from(`${privateKey}:`).toString(
          "base64",
        )}`,
      },
    },
  );

  if (response.status === 404) {
    return {
      ok: true,
      skipped: true,
      reason: "not-found",
    };
  }

  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`imagekit-delete-failed:${response.status}:${body}`);
  }

  return {
    ok: true,
    deleted: true,
  };
}

async function deleteImageKitFiles(fileIds) {
  const results = [];

  for (const fileId of uniqueCleanStrings(fileIds)) {
    try {
      const result = await deleteImageKitFile(fileId);
      results.push({ fileId, ...result });
    } catch (error) {
      console.warn("Failed to delete ImageKit file", fileId, error.message);
      results.push({
        fileId,
        ok: false,
        error: error.message,
      });
    }
  }

  return results;
}

async function deleteQueryBatch(query, batchSize = 400) {
  let deleted = 0;

  while (true) {
    const snap = await query.limit(batchSize).get();
    if (snap.empty) break;

    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    deleted += snap.size;

    if (snap.size < batchSize) break;
  }

  return deleted;
}

async function deletePostSubcollections(postRef) {
  let deletedLikes = 0;
  let deletedComments = 0;
  let deletedCommentLikes = 0;

  deletedLikes += await deleteQueryBatch(postRef.collection("likes"), 400);

  while (true) {
    const commentsSnap = await postRef.collection("comments").limit(100).get();
    if (commentsSnap.empty) break;

    for (const commentDoc of commentsSnap.docs) {
      deletedCommentLikes += await deleteQueryBatch(
        commentDoc.ref.collection("likes"),
        400,
      );
    }

    const batch = db.batch();
    commentsSnap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();

    deletedComments += commentsSnap.size;
  }

  return {
    deletedLikes,
    deletedComments,
    deletedCommentLikes,
  };
}

async function deleteUserRootSubcollections(uid) {
  const userRef = db.collection("users").doc(uid);

  const names = [
    "fcmTokens",
    "followers",
    "following",
    "savedPosts",
    "notifications",
    "blocked",
  ];

  const result = {};

  for (const name of names) {
    result[name] = await deleteQueryBatch(userRef.collection(name), 300).catch(
      (error) => {
        console.warn(`Failed to delete users/${uid}/${name}`, error.message);
        return 0;
      },
    );
  }

  return result;
}

async function deleteUserPostsCompletely(uid) {
  let deletedPosts = 0;
  let deletedLikes = 0;
  let deletedComments = 0;
  let deletedCommentLikes = 0;
  let deletedSavedPosts = 0;
  let deletedNotifications = 0;
  let mediaDeletes = [];

  while (true) {
    const snap = await db
      .collection("posts")
      .where("userId", "==", uid)
      .limit(60)
      .get();

    if (snap.empty) break;

    const batch = db.batch();

    for (const postDoc of snap.docs) {
      const postData = postDoc.data() || {};
      const fileIds = imageKitFileIdsFromPost(postData);
      const sub = await deletePostSubcollections(postDoc.ref);

      deletedLikes += sub.deletedLikes || 0;
      deletedComments += sub.deletedComments || 0;
      deletedCommentLikes += sub.deletedCommentLikes || 0;

      deletedSavedPosts += await deleteQueryBatch(
        db.collectionGroup("savedPosts").where("postId", "==", postDoc.id),
        300,
      ).catch((error) => {
        console.warn(
          "Failed to delete savedPosts for post",
          postDoc.id,
          error.message,
        );
        return 0;
      });

      deletedNotifications += await deleteQueryBatch(
        db.collectionGroup("notifications").where("postId", "==", postDoc.id),
        300,
      ).catch((error) => {
        console.warn(
          "Failed to delete notifications for post",
          postDoc.id,
          error.message,
        );
        return 0;
      });

      mediaDeletes = mediaDeletes.concat(await deleteImageKitFiles(fileIds));

      batch.delete(postDoc.ref);
      deletedPosts += 1;
    }

    await batch.commit();

    if (snap.size < 60) break;
  }

  return {
    deletedPosts,
    deletedLikes,
    deletedComments,
    deletedCommentLikes,
    deletedSavedPosts,
    deletedNotifications,
    mediaDeletes,
  };
}

async function deleteUserStoriesCompletely(uid) {
  let deletedStories = 0;
  let mediaDeletes = [];

  while (true) {
    const snap = await db
      .collection("stories")
      .where("uid", "==", uid)
      .limit(100)
      .get();

    if (snap.empty) break;

    const batch = db.batch();

    for (const storyDoc of snap.docs) {
      const storyData = storyDoc.data() || {};
      mediaDeletes = mediaDeletes.concat(
        await deleteImageKitFiles(imageKitFileIdsFromStory(storyData)),
      );

      batch.delete(storyDoc.ref);
      deletedStories += 1;
    }

    await batch.commit();

    if (snap.size < 100) break;
  }

  return {
    deletedStories,
    storyMediaDeletes: mediaDeletes,
  };
}

async function deleteUserConversationsCompletely(uid) {
  let deletedConversations = 0;
  let deletedMessages = 0;

  while (true) {
    const snap = await db
      .collection("conversations")
      .where("participants", "array-contains", uid)
      .limit(80)
      .get();

    if (snap.empty) break;

    const batch = db.batch();

    for (const convoDoc of snap.docs) {
      deletedMessages += await deleteQueryBatch(
        convoDoc.ref.collection("messages"),
        400,
      );

      batch.delete(convoDoc.ref);
      deletedConversations += 1;
    }

    await batch.commit();

    if (snap.size < 80) break;
  }

  return {
    deletedConversations,
    deletedMessages,
  };
}
async function deleteUserReactionsEverywhere(uid) {
  let deletedPostLikes = 0;
  let deletedCommentLikes = 0;
  let deletedCommentsOnOtherPosts = 0;

  while (true) {
    const snap = await db
      .collectionGroup("likes")
      .where("uid", "==", uid)
      .limit(100)
      .get();

    if (snap.empty) break;

    for (const likeDoc of snap.docs) {
      const likedParentRef = likeDoc.ref.parent.parent;

      if (!likedParentRef) {
        await likeDoc.ref.delete().catch(() => {});
        continue;
      }

      const parentCollection = likedParentRef.parent.id;
      const batch = db.batch();

      batch.delete(likeDoc.ref);

      if (parentCollection === "posts") {
        batch.update(likedParentRef, {
          likesCount: FieldValue.increment(-1),
        });
        deletedPostLikes += 1;
      } else if (parentCollection === "comments") {
        batch.update(likedParentRef, {
          likesCount: FieldValue.increment(-1),
        });
        deletedCommentLikes += 1;
      }

      await batch.commit().catch(async (error) => {
        console.warn(
          "Failed to delete user like",
          likeDoc.ref.path,
          error.message,
        );

        await likeDoc.ref.delete().catch(() => {});
      });
    }

    if (snap.size < 100) break;
  }

  while (true) {
    const snap = await db
      .collectionGroup("comments")
      .where("userId", "==", uid)
      .limit(80)
      .get();

    if (snap.empty) break;

    for (const commentDoc of snap.docs) {
      const postRef = commentDoc.ref.parent.parent;

      await deleteQueryBatch(commentDoc.ref.collection("likes"), 300).catch(
        () => 0,
      );

      const batch = db.batch();

      batch.delete(commentDoc.ref);

      if (postRef) {
        batch.update(postRef, {
          commentsCount: FieldValue.increment(-1),
        });
      }

      await batch.commit().catch(async (error) => {
        console.warn(
          "Failed to delete user comment",
          commentDoc.ref.path,
          error.message,
        );

        await commentDoc.ref.delete().catch(() => {});
      });

      deletedCommentsOnOtherPosts += 1;
    }

    if (snap.size < 80) break;
  }

  return {
    deletedPostLikes,
    deletedCommentLikes,
    deletedCommentsOnOtherPosts,
  };
}

async function deleteUserReferencesEverywhere(uid) {
  const result = {};

  result.followers = await deleteQueryBatch(
    db.collectionGroup("followers").where("uid", "==", uid),
    300,
  ).catch(() => 0);

  result.following = await deleteQueryBatch(
    db.collectionGroup("following").where("uid", "==", uid),
    300,
  ).catch(() => 0);

  result.blocked = await deleteQueryBatch(
    db.collectionGroup("blocked").where("uid", "==", uid),
    300,
  ).catch(() => 0);

  result.notificationsFromUser = await deleteQueryBatch(
    db.collectionGroup("notifications").where("fromUid", "==", uid),
    300,
  ).catch(() => 0);

  result.savedPostsOwnedByUser = await deleteQueryBatch(
    db.collectionGroup("savedPosts").where("ownerUid", "==", uid),
    300,
  ).catch(() => 0);

  return result;
}

async function deleteUserCallsCompletely(uid) {
  let deletedCalls = 0;
  const fields = ["callerUid", "receiverUid"];

  for (const field of fields) {
    deletedCalls += await deleteQueryBatch(
      db.collection("calls").where(field, "==", uid),
      200,
    ).catch(() => 0);
  }

  return {
    deletedCalls,
  };
}
async function countQuery(query) {
  const snap = await query.count().get();
  const data = snap.data() || {};
  return Number(data.count || 0);
}

async function safeCount(label, query) {
  try {
    return {
      label,
      value: await countQuery(query),
      error: "",
    };
  } catch (error) {
    console.warn("stats count failed", label, error.message);

    return {
      label,
      value: null,
      error: error.message || "count-failed",
    };
  }
}

function timestampToIso(value) {
  try {
    if (!value) return "";
    if (typeof value.toDate === "function") return value.toDate().toISOString();
    if (value instanceof Date) return value.toISOString();
  } catch (_) {}

  return "";
}

function readPossibleFileSize(data = {}) {
  const values = [
    data.fileSize,
    data.mediaFileSize,
    data.mediaSize,
    data.sizeBytes,
    data.mediaSizeBytes,
    data.thumbnailFileSize,
    data.thumbnailSizeBytes,
  ];

  let total = 0;

  values.forEach((value) => {
    const n = Number(value || 0);
    if (Number.isFinite(n) && n > 0) total += n;
  });

  return total;
}

async function buildMediaSummary() {
  let postsWithMedia = 0;
  let storiesWithMedia = 0;
  let reels = 0;
  let images = 0;
  let knownFileIds = 0;
  let knownBytes = 0;
  const sampleLimit = 1000;

  const postsSnap = await db.collection("posts").limit(sampleLimit).get();

  postsSnap.docs.forEach((doc) => {
    const data = doc.data() || {};
    const mediaUrl = cleanText(data.mediaUrl);
    const thumbnailUrl = cleanText(data.thumbnailUrl);
    const type = cleanText(data.type).toLowerCase();

    if (mediaUrl || thumbnailUrl) postsWithMedia += 1;
    if (type === "reel") reels += 1;
    if (type === "image") images += 1;

    knownFileIds += imageKitFileIdsFromPost(data).length;
    knownBytes += readPossibleFileSize(data);
  });

  const storiesSnap = await db.collection("stories").limit(sampleLimit).get();

  storiesSnap.docs.forEach((doc) => {
    const data = doc.data() || {};
    const mediaUrl = cleanText(data.mediaUrl);
    const thumbnailUrl = cleanText(data.thumbnailUrl);

    if (mediaUrl || thumbnailUrl) storiesWithMedia += 1;

    knownFileIds += imageKitFileIdsFromStory(data).length;
    knownBytes += readPossibleFileSize(data);
  });

  return {
    postsSampled: postsSnap.size,
    storiesSampled: storiesSnap.size,
    sampleLimit,
    postsWithMedia,
    storiesWithMedia,
    imagePostsInSample: images,
    reelPostsInSample: reels,
    knownImageKitFileIds: knownFileIds,
    knownStoredBytes: knownBytes,
    knownStoredMB: Number((knownBytes / 1024 / 1024).toFixed(2)),
    note:
      "Known storage is accurate only for files where file size/fileId was saved in Firestore. ImageKit dashboard remains the source of truth for total storage and bandwidth.",
  };
}

async function getRecentAdminLogs(limit = 8) {
  try {
    const snap = await db
      .collection("adminLogs")
      .orderBy("createdAt", "desc")
      .limit(limit)
      .get();

    return snap.docs.map((doc) => {
      const data = doc.data() || {};

      return {
        id: doc.id,
        action: cleanText(data.action),
        adminUid: cleanText(data.adminUid),
        targetUid: cleanText(data.targetUid),
        reason: cleanText(data.reason),
        createdAt: timestampToIso(data.createdAt),
      };
    });
  } catch (error) {
    console.warn("Failed to read admin logs", error.message);
    return [];
  }
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "MONO Notification Server",
  });
});

app.get("/health", (req, res) => {
  res.json({ ok: true });
});

app.get("/debug/imagekit", verifyUser, verifyAdmin, async (req, res) => {
  if (process.env.VERCEL || process.env.NODE_ENV === "production") {
    return res.status(404).json({ ok: false, error: "Not found" });
  }
  const privateKey = getImageKitPrivateKey();

  return res.json({
    ok: true,
    hasPrivateKey: Boolean(privateKey),
    privateKeyLooksValid: privateKey.startsWith("private_"),
    env: {
      IMAGEKIT_PRIVATE_KEY: Boolean(process.env.IMAGEKIT_PRIVATE_KEY),
      IMAGEKIT_PRIVATE_API_KEY: Boolean(process.env.IMAGEKIT_PRIVATE_API_KEY),
      IMAGEKIT_PRIVATE: Boolean(process.env.IMAGEKIT_PRIVATE),
      IMAGEKIT_SECRET_KEY: Boolean(process.env.IMAGEKIT_SECRET_KEY),
    },
  });
});
function getImageKitPrivateKey() {
  const candidates = [
    process.env.IMAGEKIT_PRIVATE_KEY,
    process.env.IMAGEKIT_PRIVATE_API_KEY,
    process.env.IMAGEKIT_PRIVATE,
    process.env.IMAGEKIT_SECRET_KEY,
  ];

  for (const value of candidates) {
    const key = cleanText(value)
      .replace(/^["']|["']$/g, "")
      .replace(/\\n/g, "\n");

    if (key) return key;
  }

  return "";
}

const MEDIA_LIMITS = Object.freeze({
  image: { maxBytes: 10 * 1024 * 1024, dailyCount: 60 },
  video: { maxBytes: 250 * 1024 * 1024, dailyCount: 12 },
  audio: { maxBytes: 25 * 1024 * 1024, dailyCount: 60 },
});
const configuredMediaDailyBytes = Number(
  process.env.IMAGEKIT_DAILY_BYTES_PER_USER,
);
const MEDIA_DAILY_BYTES =
  Number.isSafeInteger(configuredMediaDailyBytes) &&
  configuredMediaDailyBytes > 0
    ? configuredMediaDailyBytes
    : 750 * 1024 * 1024;
const MEDIA_SESSION_SECONDS = 5 * 60;

function mediaDayKey() {
  return new Date().toISOString().slice(0, 10).replaceAll("-", "");
}

function safeMediaExtension(value) {
  const ext = cleanText(value).toLowerCase().replace(/[^a-z0-9]/g, "");
  return ext && ext.length <= 8 ? ext : "";
}

function mediaExtensionAllowed(type, ext) {
  const allowed = {
    image: new Set(["jpg", "jpeg", "png", "webp", "gif"]),
    video: new Set(["mp4", "mov", "m4v", "webm", "mkv"]),
    audio: new Set(["m4a", "aac", "mp3", "wav", "webm", "ogg", "opus"]),
  };
  return allowed[type]?.has(ext) === true;
}

async function validateMediaFolder(uid, requestedFolder) {
  const folder = cleanText(requestedFolder)
    .replaceAll("\\", "/")
    .replace(/^\/+|\/+$/g, "");
  if (
    !folder ||
    folder.length > 180 ||
    folder.includes("..") ||
    !/^[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(folder)
  ) {
    return "";
  }

  const escapedUid = cleanText(uid).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const ownedPatterns = [
    new RegExp(`^avatars/${escapedUid}$`),
    new RegExp(`^covers/${escapedUid}$`),
    new RegExp(`^posts/(images|videos|thumbnails)/${escapedUid}$`),
    new RegExp(`^stories/(images|videos)/${escapedUid}$`),
    new RegExp(`^ads/${escapedUid}(/payments)?$`),
  ];
  if (ownedPatterns.some((pattern) => pattern.test(folder))) return folder;

  const chatMatch = /^chats\/([^/]+)\/(media|voice)$/.exec(folder);
  if (chatMatch && isSafeDocumentId(chatMatch[1])) {
    const snap = await db.collection("conversations").doc(chatMatch[1]).get();
    const participants = uniqueCleanStrings(snap.data()?.participants || []);
    if (snap.exists && participants.includes(uid)) return folder;
  }
  return "";
}

async function reserveMediaUpload({ uid, type, bytes, folder, extension }) {
  const uploadId = randomUUID();
  const day = mediaDayKey();
  const quotaRef = db.collection("_mediaUploadQuotas").doc(`${uid}_${day}`);
  const sessionRef = db.collection("_mediaUploadSessions").doc(uploadId);
  const expiresAt = Timestamp.fromMillis(
    Date.now() + MEDIA_SESSION_SECONDS * 1000,
  );

  await db.runTransaction(async (tx) => {
    const quotaSnap = await tx.get(quotaRef);
    const quota = quotaSnap.data() || {};
    const totalBytes = Number(quota.totalBytes || 0);
    const typeCount = Number(quota[`${type}Count`] || 0);
    if (
      totalBytes + bytes > MEDIA_DAILY_BYTES ||
      typeCount >= MEDIA_LIMITS[type].dailyCount
    ) {
      const error = new Error("media-daily-quota-exceeded");
      error.statusCode = 429;
      throw error;
    }

    tx.set(
      quotaRef,
      {
        uid,
        day,
        totalBytes: totalBytes + bytes,
        [`${type}Count`]: typeCount + 1,
        updatedAt: FieldValue.serverTimestamp(),
        expiresAt: Timestamp.fromMillis(Date.now() + 3 * 24 * 3600 * 1000),
      },
      { merge: true },
    );
    tx.create(sessionRef, {
      uploadId,
      ownerUid: uid,
      type,
      expectedBytes: bytes,
      folder,
      extension,
      fileName: `${uploadId}.${extension}`,
      status: "reserved",
      day,
      createdAt: FieldValue.serverTimestamp(),
      expiresAt,
    });
  });

  return { uploadId, sessionRef, expiresAt };
}

async function getImageKitFileDetails(fileId) {
  const privateKey = getImageKitPrivateKey();
  const response = await fetch(
    `https://api.imagekit.io/v1/files/${encodeURIComponent(fileId)}/details`,
    {
      headers: {
        Authorization: `Basic ${Buffer.from(`${privateKey}:`).toString(
          "base64",
        )}`,
      },
    },
  );
  if (!response.ok) {
    throw new Error(`imagekit-details-failed:${response.status}`);
  }
  return response.json();
}

async function releaseMediaReservation(uploadId, uid) {
  const sessionRef = db.collection("_mediaUploadSessions").doc(uploadId);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(sessionRef);
    if (!snap.exists) return;
    const data = snap.data() || {};
    if (
      cleanText(data.ownerUid) !== uid ||
      cleanText(data.status) !== "reserved"
    ) {
      return;
    }
    const type = cleanText(data.type);
    const quotaRef = db
      .collection("_mediaUploadQuotas")
      .doc(`${uid}_${cleanText(data.day)}`);
    tx.set(
      quotaRef,
      {
        totalBytes: FieldValue.increment(-Number(data.expectedBytes || 0)),
        [`${type}Count`]: FieldValue.increment(-1),
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );
    tx.update(sessionRef, {
      status: "cancelled",
      cancelledAt: FieldValue.serverTimestamp(),
    });
  });
}

app.post(
  "/imagekit-upload-auth",
  verifyUser,
  secureAction("imagekit_auth", 80, 3600, { messaging: false }),
  async (req, res) => {
  try {
    const uid = req.user.uid;
    const privateKey = getImageKitPrivateKey();

    if (!privateKey) {
      console.error("ImageKit upload auth failed: missing private key env", {
        has_IMAGEKIT_PRIVATE_KEY: Boolean(process.env.IMAGEKIT_PRIVATE_KEY),
        has_IMAGEKIT_PRIVATE_API_KEY: Boolean(
          process.env.IMAGEKIT_PRIVATE_API_KEY,
        ),
        has_IMAGEKIT_PRIVATE: Boolean(process.env.IMAGEKIT_PRIVATE),
        has_IMAGEKIT_SECRET_KEY: Boolean(process.env.IMAGEKIT_SECRET_KEY),
      });

      return res.status(503).json({
        ok: false,
        code: "missing_imagekit_private_key",
        error:
          "IMAGEKIT_PRIVATE_KEY is missing on the server. Add it in Vercel Environment Variables, then redeploy.",
      });
    }

    if (!privateKey.startsWith("private_")) {
      console.error("ImageKit upload auth failed: invalid private key format");

      return res.status(503).json({
        ok: false,
        code: "invalid_imagekit_private_key",
        error:
          "IMAGEKIT_PRIVATE_KEY exists but does not look like an ImageKit private key.",
      });
    }

    const type = cleanText(req.body.type).toLowerCase();
    const bytes = Number(req.body.bytes || 0);
    const extension = safeMediaExtension(req.body.extension);
    const folder = await validateMediaFolder(uid, req.body.folder);
    const limits = MEDIA_LIMITS[type];
    if (
      !limits ||
      !Number.isSafeInteger(bytes) ||
      bytes <= 0 ||
      bytes > limits.maxBytes ||
      !mediaExtensionAllowed(type, extension) ||
      !folder
    ) {
      return res.status(400).json({
        ok: false,
        code: "invalid_upload_request",
        error: "Invalid upload type, size, extension, or folder",
      });
    }

    const reservation = await reserveMediaUpload({
      uid,
      type,
      bytes,
      folder,
      extension,
    });
    const token = randomBytes(24).toString("hex");
    const expire = Math.floor(reservation.expiresAt.toMillis() / 1000);

    const signature = createHmac("sha1", privateKey)
      .update(`${token}${expire}`)
      .digest("hex");

    return res.json({
      ok: true,
      token,
      expire,
      signature,
      uploadId: reservation.uploadId,
      folder: `/${folder}`,
      fileName: `${reservation.uploadId}.${extension}`,
      maxBytes: limits.maxBytes,
    });
  } catch (error) {
    console.error("imagekit-upload-auth error", error);

    return res.status(error.statusCode || 500).json({
      ok: false,
      code:
        error.message === "media-daily-quota-exceeded"
          ? "media_daily_quota_exceeded"
          : "imagekit_upload_auth_failed",
      error:
        error.message === "media-daily-quota-exceeded"
          ? "Daily media upload quota exceeded"
          : "Server error",
      requestId: req.requestId,
    });
  }
},
);

app.post(
  "/imagekit-upload-complete",
  verifyUser,
  secureAction("imagekit_complete", 100, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const uploadId = cleanText(req.body.uploadId);
      const fileId = cleanText(req.body.fileId);
      if (!isSafeDocumentId(uploadId) || !isSafeDocumentId(fileId)) {
        return res.status(400).json({ ok: false, error: "Invalid upload" });
      }
      const sessionRef = db.collection("_mediaUploadSessions").doc(uploadId);
      const sessionSnap = await sessionRef.get();
      const session = sessionSnap.data() || {};
      if (
        !sessionSnap.exists ||
        cleanText(session.ownerUid) !== uid ||
        cleanText(session.status) !== "reserved" ||
        session.expiresAt?.toMillis?.() < Date.now()
      ) {
        return res.status(403).json({ ok: false, error: "Upload not owned" });
      }

      const details = await getImageKitFileDetails(fileId);
      const expectedPath = `/${cleanText(session.folder)}/${cleanText(
        session.fileName,
      )}`;
      const actualPath = cleanText(details.filePath);
      const actualBytes = Number(details.size || 0);
      if (
        actualPath !== expectedPath ||
        actualBytes <= 0 ||
        actualBytes > Number(session.expectedBytes || 0)
      ) {
        await deleteImageKitFile(fileId).catch(() => {});
        await releaseMediaReservation(uploadId, uid);
        return res.status(400).json({
          ok: false,
          error: "Uploaded file does not match its reservation",
        });
      }

      const assetRef = db.collection("_mediaAssets").doc(fileId);
      await db.runTransaction(async (tx) => {
        const freshSession = await tx.get(sessionRef);
        if (cleanText(freshSession.data()?.status) !== "reserved") {
          const error = new Error("upload-already-finalized");
          error.statusCode = 409;
          throw error;
        }
        tx.create(assetRef, {
          fileId,
          uploadId,
          ownerUid: uid,
          type: cleanText(session.type),
          bytes: actualBytes,
          filePath: actualPath,
          url: cleanText(details.url || req.body.url),
          status: "active",
          createdAt: FieldValue.serverTimestamp(),
        });
        tx.update(sessionRef, {
          status: "completed",
          fileId,
          actualBytes,
          completedAt: FieldValue.serverTimestamp(),
        });
      });
      return res.json({ ok: true, fileId, owned: true });
    } catch (error) {
      console.error("imagekit-upload-complete error", error);
      return res.status(error.statusCode || 500).json({
        ok: false,
        error: "Could not verify uploaded file",
        requestId: req.requestId,
      });
    }
  },
);

app.post(
  "/imagekit-upload-cancel",
  verifyUser,
  secureAction("imagekit_cancel", 100, 3600, { messaging: false }),
  async (req, res) => {
    const uid = req.user.uid;
    const uploadId = cleanText(req.body.uploadId);
    const fileId = cleanText(req.body.fileId);
    if (!isSafeDocumentId(uploadId)) {
      return res.status(400).json({ ok: false, error: "Invalid uploadId" });
    }
    if (isSafeDocumentId(fileId)) {
      const session = (
        await db.collection("_mediaUploadSessions").doc(uploadId).get()
      ).data();
      if (
        cleanText(session?.ownerUid) === uid &&
        cleanText(session?.fileName) &&
        cleanText(session?.folder)
      ) {
        const details = await getImageKitFileDetails(fileId).catch(() => null);
        const expected = `/${cleanText(session.folder)}/${cleanText(
          session.fileName,
        )}`;
        if (cleanText(details?.filePath) === expected) {
          await deleteImageKitFile(fileId).catch(() => {});
        }
      }
    }
    await releaseMediaReservation(uploadId, uid);
    return res.json({ ok: true, cancelled: true });
  },
);
app.post(
  "/send-message",
  verifyUser,
  secureAction("send_message", 120),
  async (req, res) => {
  try {
    const senderUid = req.user.uid;
    const toUid = cleanText(req.body.toUid);
    const convoId = cleanText(req.body.convoId);
    const messageId = cleanText(req.body.messageId);

    if (!toUid || !convoId) {
      return res.status(400).json({
        ok: false,
        error: "toUid and convoId are required",
      });
    }

    if (toUid === senderUid) {
      return res.status(400).json({
        ok: false,
        error: "Cannot send notification to yourself",
      });
    }

    await requireActiveUser(toUid, { messaging: true });
    await requireConversationParticipants(convoId, senderUid, toUid);
    await requireNoBlockBetween(senderUid, toUid);
    if (!isSafeDocumentId(messageId)) {
      return res.status(400).json({
        ok: false,
        error: "A valid messageId is required",
      });
    }
    const messageSnap = await db
      .collection("conversations")
      .doc(convoId)
      .collection("messages")
      .doc(messageId)
      .get();
    const messageData = messageSnap.data() || {};
    if (
      !messageSnap.exists ||
      cleanText(messageData.fromUid) !== senderUid ||
      cleanText(messageData.toUid) !== toUid
    ) {
      return res.status(403).json({
        ok: false,
        error: "Message permission denied",
      });
    }
    const verifiedText = cleanText(messageData.text);

    const senderName = await getUserTitle(senderUid);

    const result = await sendPushToUser({
      uid: toUid,
      title: senderName,
      body: shortText(verifiedText, 100) || "أرسل لك رسالة جديدة",
      collapseKey: `chat_${convoId}`,
      tag: `chat_${convoId}`,
      data: {
        type: "message",
        notificationType: "message",
        convoId,
        messageId,
        fromUid: senderUid,
        toUid,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });

    return res.json(result);
  } catch (error) {
    console.error("send-message error", error);
    return res.status(error.statusCode || 500).json({
      ok: false,
      error:
        error.statusCode === 403 ? "Conversation permission denied" : "Server error",
      requestId: req.requestId,
    });
  }
},
);

app.post(
  "/send-call",
  verifyUser,
  secureAction("send_call", 10, 60),
  async (req, res) => {
  try {
    const callerUid = req.user.uid;
    const receiverUid = cleanText(req.body.receiverUid);
    const callId = cleanText(req.body.callId);
    const conversationId = cleanText(
      req.body.conversationId || req.body.convoId,
    );

    const callType = cleanText(req.body.callType) === "video" ? "video" : "voice";

    if (!receiverUid || !callId || !conversationId) {
      return res.status(400).json({
        ok: false,
        error: "receiverUid, callId and conversationId are required",
      });
    }

    if (receiverUid === callerUid) {
      return res.status(400).json({
        ok: false,
        error: "Cannot call yourself",
      });
    }

    await requireActiveUser(receiverUid, { messaging: true });
    await requireNoBlockBetween(callerUid, receiverUid);
    await requireConversationParticipants(
      conversationId,
      callerUid,
      receiverUid,
    );
    if (!isSafeDocumentId(callId)) {
      return res.status(400).json({ ok: false, error: "Invalid callId" });
    }
    const callSnap = await db.collection("calls").doc(callId).get();
    const callData = callSnap.data() || {};
    if (
      !callSnap.exists ||
      cleanText(callData.callerUid) !== callerUid ||
      cleanText(callData.receiverUid) !== receiverUid ||
      cleanText(callData.status).toLowerCase() !== "ringing" ||
      cleanText(callData.type).toLowerCase() !== callType ||
      cleanText(callData.conversationId) !== conversationId
    ) {
      return res.status(403).json({
        ok: false,
        error: "Call permission denied",
      });
    }

    const hasDuplicateActiveCall = await hasActiveCallBetweenUsers({
      callerUid,
      receiverUid,
      callId,
    });

    if (hasDuplicateActiveCall) {
      return res.status(409).json({
        ok: false,
        duplicate: true,
        error: "There is already an active call between these users",
      });
    }

    const fallbackCallerName = cleanText(req.body.callerName);
    const callerName = fallbackCallerName || (await getUserTitle(callerUid));

    const result = await sendDataOnlyPushToUser({
      uid: receiverUid,
      collapseKey: `call_${callId}`,
      data: {
        type: "incoming_call",
        notificationType: "call",
        callId,
        conversationId,
        convoId: conversationId,
        callerUid,
        receiverUid,
        callType,
        callerName,
        callerUsername: callerName,
        senderName: callerName,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });

    return res.json(result);
  } catch (error) {
    console.error("send-call error", error);
    return res.status(error.statusCode || 500).json({
      ok: false,
      error: "Server error",
      requestId: req.requestId,
    });
  }
},
);

app.post(
  "/send-notification",
  verifyUser,
  secureAction("send_notification", 60),
  async (req, res) => {
  try {
    const fromUid = req.user.uid;
    const toUid = cleanText(req.body.toUid);
    const notificationId = cleanText(req.body.notificationId);
    const notificationType = cleanText(req.body.notificationType);
    const fallbackText = cleanText(req.body.text);
    const postId = cleanText(req.body.postId);
    const commentId = cleanText(req.body.commentId);

    if (!toUid) {
      return res.status(400).json({
        ok: false,
        error: "toUid is required",
      });
    }

    if (toUid === fromUid) {
      return res.status(400).json({
        ok: false,
        error: "Cannot send notification to yourself",
      });
    }

    const supportedTypes = new Set(["like", "comment", "comment_like", "follow"]);
    if (!supportedTypes.has(notificationType)) {
      return res.status(400).json({
        ok: false,
        error: "Unsupported notification type",
      });
    }

    await requireActiveUser(toUid);
    await requireNoBlockBetween(fromUid, toUid);
    if (!isSafeDocumentId(notificationId)) {
      return res.status(400).json({
        ok: false,
        error: "A valid notificationId is required",
      });
    }
    const notificationSnap = await db
      .collection("users")
      .doc(toUid)
      .collection("notifications")
      .doc(notificationId)
      .get();
    const notificationData = notificationSnap.data() || {};
    if (
      !notificationSnap.exists ||
      cleanText(notificationData.fromUid) !== fromUid ||
      cleanText(notificationData.type).toLowerCase() !== notificationType ||
      (postId && cleanText(notificationData.postId) !== postId) ||
      (commentId && cleanText(notificationData.commentId) !== commentId)
    ) {
      return res.status(403).json({
        ok: false,
        error: "Notification permission denied",
      });
    }

    const fromName = await getUserTitle(fromUid);

    let type = "notification";
    let title = "إشعار جديد";
    let body = fallbackText || "لديك إشعار جديد";
    let collapseKey = "mono_general";
    let tag = notificationId
      ? `notification_${notificationId}`
      : "mono_general";

    if (notificationType === "like") {
      type = "like";
      title = "إعجاب جديد";
      body = `${fromName} أعجب بمنشورك`;
      collapseKey = postId ? `post_${postId}` : "mono_like";
      tag = postId ? `post_${postId}` : "mono_like";
    } else if (notificationType === "comment") {
      type = "comment";
      title = "تعليق جديد";
      body = fallbackText
        ? `${fromName}: ${shortText(fallbackText, 90)}`
        : `${fromName} علّق على منشورك`;
      collapseKey = postId ? `post_${postId}` : "mono_comment";
      tag = postId ? `post_${postId}` : "mono_comment";
    } else if (notificationType === "comment_like") {
      type = "comment_like";
      title = "إعجاب بتعليقك";
      body = `${fromName} أعجب بتعليقك`;
      collapseKey = postId ? `post_${postId}` : "mono_comment_like";
      tag = postId ? `post_${postId}` : "mono_comment_like";
    } else if (notificationType === "follow") {
      type = "follow";
      title = "متابع جديد";
      body = `${fromName} بدأ بمتابعتك`;
      collapseKey = `user_${fromUid}`;
      tag = `user_${fromUid}`;
    }

    const result = await sendPushToUser({
      uid: toUid,
      title,
      body,
      collapseKey,
      tag,
      data: {
        type,
        notificationId,
        notificationType,
        postId,
        commentId,
        fromUid,
        toUid,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });

    return res.json(result);
  } catch (error) {
    console.error("send-notification error", error);
    return res.status(error.statusCode || 500).json({
      ok: false,
      error: error.statusCode === 403 ? "Notification permission denied" : "Server error",
      requestId: req.requestId,
    });
  }
},
);

const AD_EVENT_PLACEMENTS = new Set([
  "home_feed",
  "reels",
  "stories",
  "explore",
]);

function cleanAdPlacement(value) {
  const placement = cleanText(value).toLowerCase();
  return AD_EVENT_PLACEMENTS.has(placement) ? placement : "home_feed";
}

function cleanAdMediaType(value) {
  return cleanText(value).toLowerCase() === "video" ? "video" : "image";
}

function cleanAdDestinationType(value) {
  const type = cleanText(value).toLowerCase();
  return ["profile", "message", "call", "external_url", "none"].includes(type)
    ? type
    : "profile";
}

function cleanAdGender(value) {
  const gender = cleanText(value).toLowerCase();
  return ["male", "female", "all"].includes(gender) ? gender : "all";
}

function cleanAdInterests(value) {
  if (!Array.isArray(value)) return [];
  return uniqueCleanStrings(value)
    .map((item) => item.toLowerCase().replace(/[^\p{L}\p{N}_-]/gu, ""))
    .filter((item) => item.length >= 2 && item.length <= 40)
    .slice(0, 12);
}

function assertOwnedAdAssetData({
  asset,
  ownerUid,
  fileId,
  filePath,
  url,
  mediaType,
  purpose,
  adId = "",
}) {
  const expectedRoot = `/ads/${ownerUid}/`;
  const expectedProofRoot = `/ads/${ownerUid}/payments/`;
  const actualPath = cleanText(asset.filePath);
  const boundAdId = cleanText(asset.boundAdId);
  const expectedType = purpose === "payment_proof" ? "image" : mediaType;

  const pathAllowed = purpose === "payment_proof"
    ? actualPath.startsWith(expectedProofRoot)
    : actualPath.startsWith(expectedRoot) &&
      !actualPath.startsWith(expectedProofRoot);

  if (
    cleanText(asset.fileId) !== fileId ||
    cleanText(asset.ownerUid) !== ownerUid ||
    cleanText(asset.status).toLowerCase() !== "active" ||
    cleanText(asset.type).toLowerCase() !== expectedType ||
    actualPath !== filePath ||
    cleanText(asset.url) !== url ||
    !pathAllowed ||
    (boundAdId && boundAdId !== adId)
  ) {
    const error = new Error("ad-media-ownership-invalid");
    error.statusCode = 403;
    throw error;
  }
}

async function requireOwnedAdAsset({
  ownerUid,
  fileId,
  filePath,
  url,
  mediaType,
  purpose,
  adId = "",
}) {
  if (
    !isSafeDocumentId(fileId) ||
    !filePath.startsWith("/") ||
    !url.startsWith("https://")
  ) {
    const error = new Error("ad-media-identifiers-required");
    error.statusCode = 400;
    throw error;
  }
  const ref = db.collection("_mediaAssets").doc(fileId);
  const snap = await ref.get();
  if (!snap.exists) {
    const error = new Error("ad-media-not-registered");
    error.statusCode = 403;
    throw error;
  }
  assertOwnedAdAssetData({
    asset: snap.data() || {},
    ownerUid,
    fileId,
    filePath,
    url,
    mediaType,
    purpose,
    adId,
  });
  return ref;
}

async function verifyAdMediaOwnership(adId, adData) {
  const ownerUid = cleanText(adData.ownerUid);
  await requireOwnedAdAsset({
    ownerUid,
    fileId: cleanText(adData.mediaFileId),
    filePath: cleanText(adData.mediaFilePath),
    url: cleanText(adData.mediaUrl),
    mediaType: cleanAdMediaType(adData.mediaType),
    purpose: "ad_media",
    adId,
  });

  if (cleanText(adData.paymentProofUrl)) {
    await requireOwnedAdAsset({
      ownerUid,
      fileId: cleanText(adData.paymentProofFileId),
      filePath: cleanText(adData.paymentProofFilePath),
      url: cleanText(adData.paymentProofUrl),
      mediaType: "image",
      purpose: "payment_proof",
      adId,
    });
  }
}

app.post(
  "/ads/create",
  verifyUser,
  secureAction("ad_create", 8, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const ownerUid = req.user.uid;
      const title = cleanText(req.body.title);
      const description = cleanText(req.body.description);
      const mediaType = cleanAdMediaType(req.body.mediaType);
      const mediaUrl = cleanText(req.body.mediaUrl);
      const mediaFileId = cleanText(req.body.mediaFileId);
      const mediaFilePath = cleanText(req.body.mediaFilePath);
      const proofUrl = cleanText(req.body.paymentProofUrl);
      const proofFileId = cleanText(req.body.paymentProofFileId);
      const proofFilePath = cleanText(req.body.paymentProofFilePath);

      if (
        title.length < 3 ||
        title.length > 90 ||
        description.length < 3 ||
        description.length > 280
      ) {
        return res.status(400).json({ ok: false, error: "Invalid ad content" });
      }

      const mediaRef = await requireOwnedAdAsset({
        ownerUid,
        fileId: mediaFileId,
        filePath: mediaFilePath,
        url: mediaUrl,
        mediaType,
        purpose: "ad_media",
      });
      const proofRef = proofUrl
        ? await requireOwnedAdAsset({
            ownerUid,
            fileId: proofFileId,
            filePath: proofFilePath,
            url: proofUrl,
            mediaType: "image",
            purpose: "payment_proof",
          })
        : null;

      const owner = await getPublicUserData(ownerUid);
      const adRef = db.collection("ads").doc();
      const paymentStatus = proofUrl ? "payment_pending" : "unpaid";
      const now = FieldValue.serverTimestamp();

      await db.runTransaction(async (tx) => {
        const assetSnaps = await Promise.all([
          tx.get(mediaRef),
          ...(proofRef ? [tx.get(proofRef)] : []),
        ]);
        assertOwnedAdAssetData({
          asset: assetSnaps[0].data() || {},
          ownerUid,
          fileId: mediaFileId,
          filePath: mediaFilePath,
          url: mediaUrl,
          mediaType,
          purpose: "ad_media",
        });
        if (proofRef) {
          assertOwnedAdAssetData({
            asset: assetSnaps[1].data() || {},
            ownerUid,
            fileId: proofFileId,
            filePath: proofFilePath,
            url: proofUrl,
            mediaType: "image",
            purpose: "payment_proof",
          });
        }

        tx.create(adRef, {
          adId: adRef.id,
          ownerUid,
          ownerName: owner.username || "Advertiser",
          ownerAvatarUrl: owner.avatarUrl || "",
          businessName: shortText(req.body.businessName, 120),
          title,
          titleLower: title.toLowerCase(),
          description,
          descriptionLower: description.toLowerCase(),
          mediaType,
          mediaUrl,
          mediaFileId,
          mediaFilePath,
          placement: cleanAdPlacement(req.body.placement),
          destinationType: cleanAdDestinationType(req.body.destinationType),
          destinationValue: shortText(req.body.destinationValue, 500),
          status: "pending_review",
          reviewStatus: "pending",
          adminNote: "",
          reviewedBy: "",
          totalImpressions: 0,
          totalClicks: 0,
          maxImpressions: boundedInt(req.body.maxImpressions, 1000, 100, 1000000),
          maxClicks: boundedInt(req.body.maxClicks, 0, 0, 1000000),
          requestedDurationDays: boundedInt(
            req.body.requestedDurationDays,
            7,
            1,
            90,
          ),
          packageId: shortText(req.body.packageId, 120),
          packageName: shortText(req.body.packageName, 160),
          packageDescription: shortText(req.body.packageDescription, 500),
          targetCountry: shortText(req.body.targetCountry, 80).toLowerCase(),
          targetCity: shortText(req.body.targetCity, 80).toLowerCase(),
          targetGender: cleanAdGender(req.body.targetGender),
          targetInterests: cleanAdInterests(req.body.targetInterests),
          targetingVersion: 1,
          requestedAmount: boundedInt(req.body.requestedAmount, 0, 0, 100000000),
          paidAmount: 0,
          currency: cleanCurrency(req.body.currency),
          paymentMethod: cleanPaymentAccountType(req.body.paymentMethod),
          paymentAccountId: shortText(req.body.paymentAccountId, 120),
          paymentAccountName: shortText(req.body.paymentAccountName, 160),
          paymentAccountNumber: shortText(req.body.paymentAccountNumber, 120),
          paymentAccountHolderName: shortText(
            req.body.paymentAccountHolderName,
            160,
          ),
          paymentInstructions: shortText(req.body.paymentInstructions, 1000),
          paymentReference: shortText(req.body.paymentReference, 160),
          payerName: shortText(req.body.payerName, 160),
          paymentStatus,
          paymentAdminNote: "",
          paymentReviewedBy: "",
          paymentProofUrl: proofUrl,
          paymentProofFileId: proofFileId,
          paymentProofFilePath: proofFilePath,
          paymentProofUploadedAt: proofUrl ? now : null,
          paymentReviewedAt: null,
          paidAt: null,
          budget: 0,
          dailyBudget: 0,
          createdAt: now,
          updatedAt: now,
          reviewedAt: null,
          approvedAt: null,
          rejectedAt: null,
          startsAt: null,
          endsAt: null,
          completedAt: null,
          completionReason: "",
        });
        tx.update(mediaRef, {
          boundAdId: adRef.id,
          purpose: "ad_media",
          boundAt: now,
        });
        if (proofRef) {
          tx.update(proofRef, {
            boundAdId: adRef.id,
            purpose: "payment_proof",
            boundAt: now,
          });
        }
      });

      await addNotificationDoc({
        toUid: ownerUid,
        type: "ad_submitted",
        fromUid: ownerUid,
        text: "تم استلام إعلانك وهو الآن قيد المراجعة.",
        notificationId: `ad_submitted_${adRef.id}`,
      });
      return res.json({ ok: true, adId: adRef.id });
    } catch (error) {
      console.error("ads-create error", { requestId: req.requestId, error: error.message });
      return res.status(error.statusCode || 500).json({
        ok: false,
        error: error.statusCode ? error.message : "Server error",
        requestId: req.requestId,
      });
    }
  },
);

app.post(
  "/ads/payment-proof",
  verifyUser,
  secureAction("ad_payment_proof", 12, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const ownerUid = req.user.uid;
      const adId = cleanText(req.body.adId);
      const proofUrl = cleanText(req.body.paymentProofUrl);
      const proofFileId = cleanText(req.body.paymentProofFileId);
      const proofFilePath = cleanText(req.body.paymentProofFilePath);
      if (!isSafeDocumentId(adId)) {
        return res.status(400).json({ ok: false, error: "Invalid adId" });
      }

      const adRef = db.collection("ads").doc(adId);
      const proofRef = await requireOwnedAdAsset({
        ownerUid,
        fileId: proofFileId,
        filePath: proofFilePath,
        url: proofUrl,
        mediaType: "image",
        purpose: "payment_proof",
        adId,
      });

      await db.runTransaction(async (tx) => {
        const [adSnap, proofSnap] = await Promise.all([
          tx.get(adRef),
          tx.get(proofRef),
        ]);
        if (!adSnap.exists || cleanText(adSnap.data()?.ownerUid) !== ownerUid) {
          const error = new Error("ad-owner-required");
          error.statusCode = 403;
          throw error;
        }
        assertOwnedAdAssetData({
          asset: proofSnap.data() || {},
          ownerUid,
          fileId: proofFileId,
          filePath: proofFilePath,
          url: proofUrl,
          mediaType: "image",
          purpose: "payment_proof",
          adId,
        });
        tx.set(
          adRef,
          {
            paymentStatus: "payment_pending",
            paymentProofUrl: proofUrl,
            paymentProofFileId: proofFileId,
            paymentProofFilePath: proofFilePath,
            paymentProofUploadedAt: FieldValue.serverTimestamp(),
            paymentMethod: cleanPaymentAccountType(req.body.paymentMethod),
            paymentReference: shortText(req.body.paymentReference, 160),
            payerName: shortText(req.body.payerName, 160),
            requestedAmount: boundedInt(
              req.body.requestedAmount,
              0,
              0,
              100000000,
            ),
            currency: cleanCurrency(req.body.currency),
            paymentAdminNote: "",
            updatedAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );
        tx.update(proofRef, {
          boundAdId: adId,
          purpose: "payment_proof",
          boundAt: FieldValue.serverTimestamp(),
        });
      });

      return res.json({ ok: true, adId, paymentStatus: "payment_pending" });
    } catch (error) {
      console.error("ads-payment-proof error", {
        requestId: req.requestId,
        error: error.message,
      });
      return res.status(error.statusCode || 500).json({
        ok: false,
        error: error.statusCode ? error.message : "Server error",
        requestId: req.requestId,
      });
    }
  },
);

function timestampMillis(value) {
  if (value && typeof value.toMillis === "function") return value.toMillis();
  return 0;
}

app.post(
  "/ads/event",
  verifyUser,
  secureAction("ad_event", 120, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const viewerUid = req.user.uid;
      const adId = cleanText(req.body.adId);
      const eventType = cleanText(req.body.eventType).toLowerCase();
      const requestedPlacement = cleanText(req.body.placement).toLowerCase();

      if (
        !isSafeDocumentId(adId) ||
        !["impression", "click"].includes(eventType) ||
        !AD_EVENT_PLACEMENTS.has(requestedPlacement)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Invalid ad event",
          requestId: req.requestId,
        });
      }

      const now = Date.now();
      const day = new Date(now).toISOString().slice(0, 10).replaceAll("-", "");
      const impressionSlot = Math.floor(
        new Date(now).getUTCHours() / 8,
      );
      const adRef = db.collection("ads").doc(adId);
      const impressionRef = adRef
        .collection("impressions")
        .doc(`${viewerUid}_${day}_${impressionSlot}`);
      const eventRef = eventType === "impression"
        ? impressionRef
        : adRef.collection("clicks").doc(`${viewerUid}_${day}`);

      const result = await db.runTransaction(async (tx) => {
        const adSnap = await tx.get(adRef);
        if (!adSnap.exists) {
          const error = new Error("ad-not-found");
          error.statusCode = 404;
          throw error;
        }

        const ad = adSnap.data() || {};
        const status = cleanText(ad.status).toLowerCase();
        const paymentStatus = cleanText(ad.paymentStatus).toLowerCase();
        const placement = cleanText(ad.placement).toLowerCase();
        const ownerUid = cleanText(ad.ownerUid);
        const startsAt = timestampMillis(ad.startsAt);
        const endsAt = timestampMillis(ad.endsAt);
        const totalImpressions = Math.max(0, Number(ad.totalImpressions || 0));
        const totalClicks = Math.max(0, Number(ad.totalClicks || 0));
        const maxImpressions = Math.max(0, Number(ad.maxImpressions || 0));
        const maxClicks = Math.max(0, Number(ad.maxClicks || 0));

        if (
          status !== "running" ||
          paymentStatus !== "paid" ||
          placement !== requestedPlacement ||
          ownerUid === viewerUid ||
          (startsAt > 0 && startsAt > now)
        ) {
          const error = new Error("ad-event-not-allowed");
          error.statusCode = 403;
          throw error;
        }

        if (
          (endsAt > 0 && endsAt <= now) ||
          (maxImpressions > 0 && totalImpressions >= maxImpressions) ||
          (maxClicks > 0 && totalClicks >= maxClicks)
        ) {
          tx.set(
            adRef,
            {
              status: "completed",
              completedAt: FieldValue.serverTimestamp(),
              completionReason: "delivery_limit",
              updatedAt: FieldValue.serverTimestamp(),
            },
            { merge: true },
          );
          return { recorded: false, duplicate: false, completed: true };
        }

        const eventSnap = await tx.get(eventRef);
        if (eventSnap.exists) {
          return { recorded: false, duplicate: true, completed: false };
        }

        if (eventType === "click") {
          const impressionSnap = await tx.get(impressionRef);
          if (!impressionSnap.exists) {
            const error = new Error("impression-required-before-click");
            error.statusCode = 409;
            throw error;
          }
        }

        const nextImpressions = totalImpressions +
          (eventType === "impression" ? 1 : 0);
        const nextClicks = totalClicks + (eventType === "click" ? 1 : 0);
        const completed =
          (maxImpressions > 0 && nextImpressions >= maxImpressions) ||
          (maxClicks > 0 && nextClicks >= maxClicks);

        tx.create(eventRef, {
          adId,
          viewerUid,
          placement,
          eventType,
          day,
          impressionSlot,
          createdAt: FieldValue.serverTimestamp(),
        });
        tx.set(
          adRef,
          {
            ...(eventType === "impression"
              ? {
                  totalImpressions: nextImpressions,
                  lastImpressionAt: FieldValue.serverTimestamp(),
                }
              : {
                  totalClicks: nextClicks,
                  lastClickAt: FieldValue.serverTimestamp(),
                }),
            ...(completed
              ? {
                  status: "completed",
                  completedAt: FieldValue.serverTimestamp(),
                  completionReason: eventType === "impression"
                    ? "max_impressions"
                    : "max_clicks",
                }
              : {}),
            updatedAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );

        return { recorded: true, duplicate: false, completed };
      });

      return res.json({ ok: true, ...result });
    } catch (error) {
      console.error("ads-event error", {
        requestId: req.requestId,
        code: error.message,
      });
      return res.status(error.statusCode || 500).json({
        ok: false,
        error:
          error.statusCode && error.statusCode < 500
            ? error.message
            : "Server error",
        requestId: req.requestId,
      });
    }
  },
);

app.post(
  "/toggle-like",
  verifyUser,
  secureAction("toggle_like", 120, 3600, { messaging: false }),
  async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);

    if (!isSafeDocumentId(postId)) {
      return res.status(400).json({
        ok: false,
        error: "postId is required",
      });
    }

    const postRef = db.collection("posts").doc(postId);
    const likeRef = postRef.collection("likes").doc(actorUid);

    const result = await db.runTransaction(async (tx) => {
      const [postSnap, likeSnap] = await Promise.all([
        tx.get(postRef),
        tx.get(likeRef),
      ]);

      if (!postSnap.exists) throw new Error("post-not-found");

      const postData = postSnap.data() || {};
      const postOwnerUid = cleanText(postData.userId);

      let likesCount = Number(postData.likesCount || 0);
      const commentsCount = Number(postData.commentsCount || 0);
      let liked = false;

      if (likeSnap.exists) {
        tx.delete(likeRef);
        likesCount = Math.max(0, likesCount - 1);
      } else {
        tx.set(likeRef, {
          uid: actorUid,
          createdAt: FieldValue.serverTimestamp(),
        });
        likesCount += 1;
        liked = true;
      }

      tx.update(postRef, {
        likesCount,
        trendScore: trendScore(likesCount, commentsCount),
        engagementScore: engagementScore(postData, { likesCount }),
        trendScoreUpdatedAt: FieldValue.serverTimestamp(),
      });

      return {
        liked,
        likesCount,
        commentsCount,
        postOwnerUid,
      };
    });

    const notificationId = likeNotificationId(postId, actorUid);

    if (result.postOwnerUid && result.postOwnerUid !== actorUid) {
      if (result.liked) {
        await addNotificationDoc({
          toUid: result.postOwnerUid,
          type: "like",
          fromUid: actorUid,
          postId,
          text: "أعجب بمنشورك",
          notificationId,
        });
        await sendInteractionPush({
          toUid: result.postOwnerUid,
          type: "like",
          fromUid: actorUid,
          postId,
          notificationId,
        });
      } else {
        await deleteNotificationDoc({
          toUid: result.postOwnerUid,
          notificationId,
        });
      }
    }

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("toggle-like error", error);

    const notFound = error.message === "post-not-found";

    return res.status(notFound ? 404 : 500).json({
      ok: false,
      error: notFound ? "Post not found" : "Server error",
    });
  }
  },
);

app.post(
  "/add-comment",
  verifyUser,
  secureAction("add_comment", 80, 3600),
  async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const text = cleanText(req.body.text);
    if (!isSafeDocumentId(postId) || !text) {
      return res.status(400).json({
        ok: false,
        error: "postId and text are required",
      });
    }

    if (text.length > 500) {
      return res.status(400).json({
        ok: false,
        error: "Comment text is too long",
      });
    }

    const actor = await getPublicUserData(actorUid).catch(() => ({
      username: "user",
      avatarUrl: "",
    }));

    const postRef = db.collection("posts").doc(postId);
    const commentRef = postRef.collection("comments").doc();

    const result = await db.runTransaction(async (tx) => {
      const postSnap = await tx.get(postRef);

      if (!postSnap.exists) throw new Error("post-not-found");

      const postData = postSnap.data() || {};
      const postOwnerUid = cleanText(postData.userId);
      const likesCount = Number(postData.likesCount || 0);
      const commentsCount = Number(postData.commentsCount || 0) + 1;

      tx.set(commentRef, {
        commentId: commentRef.id,
        userId: actorUid,
        username: actor.username || "user",
        userAvatarUrl: actor.avatarUrl || "",
        text,
        createdAt: FieldValue.serverTimestamp(),
        likesCount: 0,
      });

      tx.update(postRef, {
        commentsCount,
        trendScore: trendScore(likesCount, commentsCount),
        engagementScore: engagementScore(postData, { commentsCount }),
        trendScoreUpdatedAt: FieldValue.serverTimestamp(),
      });

      return {
        commentId: commentRef.id,
        postOwnerUid,
        commentsCount,
        likesCount,
      };
    });

    if (result.postOwnerUid && result.postOwnerUid !== actorUid) {
      const notificationId = commentNotificationId(postId, result.commentId);

      await addNotificationDoc({
        toUid: result.postOwnerUid,
        type: "comment",
        fromUid: actorUid,
        postId,
        commentId: result.commentId,
        text: "علّق على منشورك",
        notificationId,
      });

      await sendInteractionPush({
        toUid: result.postOwnerUid,
        type: "comment",
        fromUid: actorUid,
        postId,
        commentId: result.commentId,
        notificationId,
        text,
      });
    }

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("add-comment error", error);

    const notFound = error.message === "post-not-found";

    return res.status(notFound ? 404 : 500).json({
      ok: false,
      error: notFound ? "Post not found" : "Server error",
    });
  }
  },
);

app.post(
  "/delete-comment",
  verifyUser,
  secureAction("delete_comment", 100, 3600, { messaging: false }),
  async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const commentId = cleanText(req.body.commentId);

    if (!isSafeDocumentId(postId) || !isSafeDocumentId(commentId)) {
      return res.status(400).json({
        ok: false,
        error: "postId and commentId are required",
      });
    }

    const postRef = db.collection("posts").doc(postId);
    const commentRef = postRef.collection("comments").doc(commentId);

    const result = await db.runTransaction(async (tx) => {
      const [postSnap, commentSnap] = await Promise.all([
        tx.get(postRef),
        tx.get(commentRef),
      ]);

      if (!postSnap.exists || !commentSnap.exists) {
        return {
          deleted: false,
        };
      }

      const postData = postSnap.data() || {};
      const commentData = commentSnap.data() || {};
      const postOwnerUid = cleanText(postData.userId);
      const commentOwnerUid = cleanText(commentData.userId);

      if (actorUid !== commentOwnerUid && actorUid !== postOwnerUid) {
        throw new Error("permission-denied");
      }

      const likesCount = Number(postData.likesCount || 0);
      const commentsCount = Math.max(
        0,
        Number(postData.commentsCount || 0) - 1,
      );

      tx.delete(commentRef);
      tx.update(postRef, {
        commentsCount,
        trendScore: trendScore(likesCount, commentsCount),
        engagementScore: engagementScore(postData, { commentsCount }),
        trendScoreUpdatedAt: FieldValue.serverTimestamp(),
      });

      return {
        deleted: true,
        postOwnerUid,
        commentOwnerUid,
        commentsCount,
        likesCount,
      };
    });

    if (result.deleted) {
      await deleteNotificationDoc({
        toUid: result.postOwnerUid,
        notificationId: commentNotificationId(postId, commentId),
      });
    }

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("delete-comment error", error);

    const denied = error.message === "permission-denied";

    return res.status(denied ? 403 : 500).json({
      ok: false,
      error: denied ? "Permission denied" : "Server error",
    });
  }
  },
);

app.post(
  "/toggle-comment-like",
  verifyUser,
  secureAction("toggle_comment_like", 160, 3600, { messaging: false }),
  async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const commentId = cleanText(req.body.commentId);

    if (!isSafeDocumentId(postId) || !isSafeDocumentId(commentId)) {
      return res.status(400).json({
        ok: false,
        error: "postId and commentId are required",
      });
    }

    const commentRef = db
      .collection("posts")
      .doc(postId)
      .collection("comments")
      .doc(commentId);

    const likeRef = commentRef.collection("likes").doc(actorUid);

    const result = await db.runTransaction(async (tx) => {
      const [commentSnap, likeSnap] = await Promise.all([
        tx.get(commentRef),
        tx.get(likeRef),
      ]);

      if (!commentSnap.exists) throw new Error("comment-not-found");

      const commentData = commentSnap.data() || {};
      const commentOwnerUid = cleanText(commentData.userId);

      let likesCount = Number(commentData.likesCount || 0);
      let liked = false;

      if (likeSnap.exists) {
        tx.delete(likeRef);
        likesCount = Math.max(0, likesCount - 1);
      } else {
        tx.set(likeRef, {
          uid: actorUid,
          createdAt: FieldValue.serverTimestamp(),
        });
        likesCount += 1;
        liked = true;
      }

      tx.update(commentRef, {
        likesCount,
      });

      return {
        liked,
        likesCount,
        commentOwnerUid,
      };
    });

    const notificationId = commentLikeNotificationId(
      postId,
      commentId,
      actorUid,
    );

    if (result.commentOwnerUid && result.commentOwnerUid !== actorUid) {
      if (result.liked) {
        await addNotificationDoc({
          toUid: result.commentOwnerUid,
          type: "comment_like",
          fromUid: actorUid,
          postId,
          commentId,
          text: "أعجب بتعليقك",
          notificationId,
        });
        await sendInteractionPush({
          toUid: result.commentOwnerUid,
          type: "comment_like",
          fromUid: actorUid,
          postId,
          commentId,
          notificationId,
        });
      } else {
        await deleteNotificationDoc({
          toUid: result.commentOwnerUid,
          notificationId,
        });
      }
    }

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("toggle-comment-like error", error);

    const notFound = error.message === "comment-not-found";

    return res.status(notFound ? 404 : 500).json({
      ok: false,
      error: notFound ? "Comment not found" : "Server error",
    });
  }
  },
);

app.post(
  "/posts/toggle-save",
  verifyUser,
  secureAction("toggle_save", 120, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const postId = cleanText(req.body.postId);
      if (!isSafeDocumentId(postId)) {
        return res.status(400).json({ ok: false, error: "Invalid postId" });
      }

      const postRef = db.collection("posts").doc(postId);
      const savedRef = db
        .collection("users")
        .doc(uid)
        .collection("savedPosts")
        .doc(postId);
      const result = await db.runTransaction(async (tx) => {
        const [postSnap, savedSnap] = await Promise.all([
          tx.get(postRef),
          tx.get(savedRef),
        ]);
        if (!postSnap.exists) {
          const error = new Error("post-not-found");
          error.statusCode = 404;
          throw error;
        }
        const post = postSnap.data() || {};
        let savesCount = Math.max(0, Number(post.savesCount || 0));
        let saved;
        if (savedSnap.exists) {
          tx.delete(savedRef);
          savesCount = Math.max(0, savesCount - 1);
          saved = false;
        } else {
          tx.create(savedRef, {
            postId,
            ownerUid: cleanText(post.userId),
            type: cleanText(post.type),
            mediaUrl: cleanText(post.mediaUrl),
            thumbnailUrl: cleanText(post.thumbnailUrl),
            caption: cleanText(post.caption),
            username: cleanText(post.username),
            userAvatarUrl: cleanText(post.userAvatarUrl),
            savedAt: FieldValue.serverTimestamp(),
          });
          savesCount += 1;
          saved = true;
        }
        tx.update(postRef, {
          savesCount,
          engagementScore: engagementScore(post, { savesCount }),
          engagementScoreUpdatedAt: FieldValue.serverTimestamp(),
        });
        return { saved, savesCount };
      });
      return res.json({ ok: true, ...result });
    } catch (error) {
      console.error("toggle-save error", error);
      return res.status(error.statusCode || 500).json({
        ok: false,
        error: error.statusCode ? error.message : "Server error",
        requestId: req.requestId,
      });
    }
  },
);

app.post(
  "/posts/share",
  verifyUser,
  secureAction("post_share", 80, 3600, { messaging: false }),
  async (req, res) => {
    try {
      const uid = req.user.uid;
      const postId = cleanText(req.body.postId);
      if (!isSafeDocumentId(postId)) {
        return res.status(400).json({ ok: false, error: "Invalid postId" });
      }
      const day = new Date().toISOString().slice(0, 10).replaceAll("-", "");
      const postRef = db.collection("posts").doc(postId);
      const shareRef = postRef.collection("shares").doc(`${uid}_${day}`);
      const result = await db.runTransaction(async (tx) => {
        const [postSnap, shareSnap] = await Promise.all([
          tx.get(postRef),
          tx.get(shareRef),
        ]);
        if (!postSnap.exists) {
          const error = new Error("post-not-found");
          error.statusCode = 404;
          throw error;
        }
        const post = postSnap.data() || {};
        const current = Math.max(
          0,
          Number(post.sharesCount || 0),
        );
        if (shareSnap.exists) {
          return { recorded: false, duplicate: true, sharesCount: current };
        }
        tx.create(shareRef, {
          uid,
          postId,
          day,
          createdAt: FieldValue.serverTimestamp(),
        });
        tx.update(postRef, {
          sharesCount: current + 1,
          engagementScore: engagementScore(post, {
            sharesCount: current + 1,
          }),
          engagementScoreUpdatedAt: FieldValue.serverTimestamp(),
        });
        return {
          recorded: true,
          duplicate: false,
          sharesCount: current + 1,
        };
      });
      return res.json({ ok: true, ...result });
    } catch (error) {
      console.error("post-share error", error);
      return res.status(error.statusCode || 500).json({
        ok: false,
        error: error.statusCode ? error.message : "Server error",
        requestId: req.requestId,
      });
    }
  },
);

app.post("/toggle-follow", verifyUser, async (req, res) => {
  try {
    const meUid = req.user.uid;
    const otherUid = cleanText(req.body.otherUid);

    if (!otherUid) {
      return res.status(400).json({
        ok: false,
        error: "otherUid is required",
      });
    }

    if (meUid === otherUid) {
      return res.status(400).json({
        ok: false,
        error: "Cannot follow yourself",
      });
    }

    const meRef = db.collection("users").doc(meUid);
    const otherRef = db.collection("users").doc(otherUid);
    const followerRef = otherRef.collection("followers").doc(meUid);
    const followingRef = meRef.collection("following").doc(otherUid);

    const result = await db.runTransaction(async (tx) => {
      const [meSnap, otherSnap, followerSnap] = await Promise.all([
        tx.get(meRef),
        tx.get(otherRef),
        tx.get(followerRef),
      ]);

      if (!meSnap.exists || !otherSnap.exists) {
        throw new Error("user-not-found");
      }

      const meData = meSnap.data() || {};
      const otherData = otherSnap.data() || {};

      let followingCount = Number(meData.followingCount || 0);
      let followersCount = Number(otherData.followersCount || 0);
      let following = false;

      if (followerSnap.exists) {
        tx.delete(followerRef);
        tx.delete(followingRef);

        followersCount = Math.max(0, followersCount - 1);
        followingCount = Math.max(0, followingCount - 1);
      } else {
        tx.set(followerRef, {
          uid: meUid,
          createdAt: FieldValue.serverTimestamp(),
        });

        tx.set(followingRef, {
          uid: otherUid,
          createdAt: FieldValue.serverTimestamp(),
        });

        followersCount += 1;
        followingCount += 1;
        following = true;
      }

      tx.update(otherRef, {
        followersCount,
      });

      tx.update(meRef, {
        followingCount,
      });

      return {
        following,
        followersCount,
        followingCount,
      };
    });

    const notificationId = followNotificationId(meUid);

    if (result.following) {
      await addNotificationDoc({
        toUid: otherUid,
        type: "follow",
        fromUid: meUid,
        postId: "",
        text: "بدأ بمتابعتك",
        notificationId,
      });
      await sendInteractionPush({
        toUid: otherUid,
        type: "follow",
        fromUid: meUid,
        notificationId,
      });
    } else {
      await deleteNotificationDoc({
        toUid: otherUid,
        notificationId,
      });
    }

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("toggle-follow error", error);

    const notFound = error.message === "user-not-found";

    return res.status(notFound ? 404 : 500).json({
      ok: false,
      error: notFound ? "User not found" : "Server error",
    });
  }
});

function boundedInt(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  const number = Number.isFinite(parsed) ? parsed : fallback;
  return Math.max(min, Math.min(max, number));
}

function cleanCurrency(value) {
  const currency = cleanText(value).toUpperCase();
  return (currency || "IQD").substring(0, 6);
}

function cleanPaymentAccountType(value) {
  const allowed = new Set([
    "zain_cash",
    "asia_hawala",
    "fastpay",
    "bank_transfer",
    "cash",
    "manual",
    "other",
  ]);
  const type = cleanText(value).toLowerCase();
  return allowed.has(type) ? type : "manual";
}

async function writeAdminLog(adminUid, action, payload = {}, result = {}) {
  await db.collection("adminLogs").add({
    action,
    adminUid,
    targetUid: cleanText(payload.targetUid),
    targetId: cleanText(
      payload.postId ||
        payload.reportId ||
        payload.adId ||
        payload.packageId ||
        payload.accountId,
    ),
    reason: cleanText(payload.reason || payload.adminNote || payload.note),
    result,
    createdAt: FieldValue.serverTimestamp(),
  });
}

async function notifyAdOwner(adId, adminUid, type, text) {
  const snap = await db.collection("ads").doc(adId).get();
  const ownerUid = cleanText(snap.data()?.ownerUid);
  if (!ownerUid) return;

  const notificationId = `${type}_${adId}`;
  await addNotificationDoc({
    toUid: ownerUid,
    type,
    fromUid: adminUid,
    text,
    notificationId,
  });

  await sendPushToUser({
    uid: ownerUid,
    title: "MONO Ads",
    body: text,
    tag: notificationId,
    collapseKey: `ad_${adId}`,
    data: {
      type,
      notificationType: "general",
      notificationId,
      adId,
      fromUid: adminUid,
      toUid: ownerUid,
    },
  }).catch((error) => {
    console.warn("Admin ad notification failed", adId, error.message);
  });
}

async function searchAdminUsers(query) {
  const cleanQuery = cleanText(query).toLowerCase();
  const users = new Map();

  const addSnapshot = (snap) => {
    snap.docs.forEach((doc) => {
      const data = doc.data() || {};
      users.set(doc.id, {
        uid: doc.id,
        username: cleanText(data.username),
        displayName: cleanText(data.displayName),
        avatarUrl: cleanText(data.avatarUrl),
        status: cleanText(data.status) || "active",
        deleted: data.deleted === true,
        isDeleted: data.isDeleted === true,
        banned: data.banned === true,
        isBanned: data.isBanned === true,
        canMessage: data.canMessage !== false,
        followersCount: Number(data.followersCount || 0),
        followingCount: Number(data.followingCount || 0),
        postsCount: Number(data.postsCount || 0),
      });
    });
  };

  if (!cleanQuery) {
    addSnapshot(
      await db.collection("users").orderBy("createdAt", "desc").limit(50).get(),
    );
    return [...users.values()];
  }

  const exact = await db.collection("users").doc(cleanText(query)).get();
  if (exact.exists) addSnapshot({ docs: [exact] });

  const end = `${cleanQuery}\uf8ff`;
  for (const field of ["usernameLower", "displayNameLower"]) {
    try {
      addSnapshot(
        await db
          .collection("users")
          .orderBy(field)
          .startAt(cleanQuery)
          .endAt(end)
          .limit(25)
          .get(),
      );
    } catch (error) {
      console.warn("Admin user search field failed", field, error.message);
    }
  }

  // Email belongs to Firebase Authentication, never to the public user doc.
  if (cleanQuery.includes("@")) {
    try {
      const authUser = await getAuth().getUserByEmail(cleanQuery);
      const userSnap = await db.collection("users").doc(authUser.uid).get();
      if (userSnap.exists) addSnapshot({ docs: [userSnap] });
    } catch (error) {
      if (error.code !== "auth/user-not-found") {
        console.warn("Admin Auth email lookup failed", error.message);
      }
    }
  }

  return [...users.values()];
}

app.post("/admin/action", verifyUser, verifyAdmin, async (req, res) => {
  const adminUid = req.user.uid;
  const payload = req.body || {};
  const action = cleanText(payload.action).toLowerCase();
  const now = FieldValue.serverTimestamp();

  try {
    let result = {};

    if (action === "search_users") {
      return res.json({
        ok: true,
        users: await searchAdminUsers(payload.query),
      });
    }

    if (action === "migrate_user_privacy_batch") {
      result = await runUserPrivacyMigrationBatch({
        adminUid,
        cursor: payload.cursor,
        dryRun: payload.dryRun !== false,
        limit: payload.limit,
        requestId: req.requestId,
      });
    } else if (
      [
        "ban_user",
        "unban_user",
        "soft_delete_user",
        "restore_user",
        "disable_messaging",
        "delete_user_posts",
        "delete_user_stories",
        "delete_user_conversations",
      ].includes(action)
    ) {
      const targetUid = cleanText(payload.targetUid);
      if (!targetUid) {
        return res.status(400).json({ ok: false, error: "targetUid is required" });
      }
      if (
        targetUid === adminUid &&
        ["ban_user", "soft_delete_user"].includes(action)
      ) {
        return res.status(400).json({
          ok: false,
          error: "Admin cannot disable own account",
        });
      }

      const targetRef = db.collection("users").doc(targetUid);

      if (action === "ban_user") {
        await targetRef.set(
          {
            status: "banned",
            banned: true,
            isBanned: true,
            deleted: false,
            isDeleted: false,
            canMessage: false,
            banReason: cleanText(payload.reason),
            bannedBy: adminUid,
            bannedAt: now,
            updatedAt: now,
            lastFcmToken: FieldValue.delete(),
            lastFcmTokenUpdatedAt: FieldValue.delete(),
          },
          { merge: true },
        );
      } else if (action === "unban_user") {
        await targetRef.set(
          {
            status: "active",
            banned: false,
            isBanned: false,
            canMessage: true,
            banReason: FieldValue.delete(),
            unbannedBy: adminUid,
            unbannedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
      } else if (action === "soft_delete_user") {
        await targetRef.set(
          {
            status: "deleted",
            deleted: true,
            isDeleted: true,
            banned: false,
            isBanned: false,
            canMessage: false,
            username: "Deleted user",
            usernameLower: "deleted user",
            displayName: "Deleted user",
            displayNameLower: "deleted user",
            bio: "",
            avatarUrl: "",
            coverPhotoUrl: "",
            deletedBy: adminUid,
            deleteReason: cleanText(payload.reason),
            deletedAt: now,
            updatedAt: now,
            lastFcmToken: FieldValue.delete(),
            lastFcmTokenUpdatedAt: FieldValue.delete(),
          },
          { merge: true },
        );
      } else if (action === "restore_user") {
        await targetRef.set(
          {
            status: "active",
            deleted: false,
            isDeleted: false,
            banned: false,
            isBanned: false,
            canMessage: true,
            restoredBy: adminUid,
            restoredAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
      } else if (action === "disable_messaging") {
        await targetRef.set(
          {
            canMessage: false,
            messagingDisabledBy: adminUid,
            messagingDisabledAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
      } else if (action === "delete_user_posts") {
        const deleted = await deleteUserPostsCompletely(targetUid);
        await targetRef.set({ postsCount: 0, updatedAt: now }, { merge: true });
        result = { deletedCount: deleted.deletedPosts || 0, details: deleted };
      } else if (action === "delete_user_stories") {
        const deleted = await deleteUserStoriesCompletely(targetUid);
        result = {
          deletedCount: deleted.deletedStories || 0,
          details: deleted,
        };
      } else if (action === "delete_user_conversations") {
        const deleted = await deleteUserConversationsCompletely(targetUid);
        result = {
          deletedCount: deleted.deletedConversations || 0,
          details: deleted,
        };
      }
    } else if (action === "update_report_status") {
      const reportId = cleanText(payload.reportId);
      const status = cleanText(payload.status).toLowerCase();
      const allowedStatuses = new Set([
        "open",
        "reviewing",
        "dismissed",
        "action_taken",
        "resolved",
      ]);
      if (!reportId || !allowedStatuses.has(status)) {
        return res.status(400).json({ ok: false, error: "Invalid report data" });
      }
      await db.collection("reports").doc(reportId).set(
        {
          status,
          reviewedBy: adminUid,
          reviewNote: cleanText(payload.note),
          reviewedAt: now,
          updatedAt: now,
        },
        { merge: true },
      );
    } else if (action === "moderation_delete_post") {
      const postId = cleanText(payload.postId);
      const reportId = cleanText(payload.reportId);
      if (!postId) {
        return res.status(400).json({ ok: false, error: "postId is required" });
      }
      await db.collection("posts").doc(postId).set(
        {
          deleted: true,
          isDeleted: true,
          moderationDeleted: true,
          moderationDeletedBy: adminUid,
          moderationDeletedReason: cleanText(payload.reason),
          moderationDeletedAt: now,
          updatedAt: now,
        },
        { merge: true },
      );
      if (reportId) {
        await db.collection("reports").doc(reportId).set(
          {
            status: "action_taken",
            reviewedBy: adminUid,
            reviewNote: cleanText(payload.reason),
            reviewedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
      }
    } else if (action === "seed_ad_defaults") {
      const defaults = [
        ["try_1d_1000", "باقة تجربة سريعة", "Quick Trial Package", 1, 1000, 3000, 1],
        ["starter_3d_5000", "باقة البداية", "Starter Package", 3, 5000, 10000, 2],
        ["shops_7d_15000", "باقة المحلات", "Local Shops Package", 7, 15000, 25000, 3],
        ["offers_10d_25000", "باقة العروض والافتتاح", "Offers & Opening Package", 10, 25000, 40000, 4],
        ["reach_14d_50000", "باقة الانتشار", "Reach Package", 14, 50000, 75000, 5],
        ["monthly_30d_100000", "باقة الشهر", "Monthly Package", 30, 100000, 140000, 6],
        ["premium_30d_200000", "باقة الانتشار الكبير", "Premium Reach Package", 30, 200000, 250000, 7],
      ];
      const batch = db.batch();
      defaults.forEach(
        ([id, nameAr, nameEn, durationDays, maxImpressions, price, sortOrder]) => {
          batch.set(
            db.collection("adPackages").doc(id),
            {
              packageId: id,
              nameAr,
              nameEn,
              descriptionAr: "",
              descriptionEn: "",
              durationDays,
              maxImpressions,
              price,
              currency: "IQD",
              active: true,
              sortOrder,
              createdBy: adminUid,
              updatedBy: adminUid,
              createdAt: now,
              updatedAt: now,
            },
            { merge: true },
          );
        },
      );
      batch.set(
        db.collection("adPaymentAccounts").doc("zain_cash_default"),
        {
          accountId: "zain_cash_default",
          nameAr: "زين كاش",
          nameEn: "Zain Cash",
          type: "zain_cash",
          accountNumber: "",
          accountHolderName: "MONO Ads",
          instructionsAr:
            "حوّل مبلغ الباقة ثم اكتب اسمك ورقم العملية وارفع صورة الوصل.",
          instructionsEn:
            "Transfer the package amount, enter your name and transaction number, then upload the receipt.",
          currency: "IQD",
          active: true,
          sortOrder: 1,
          createdBy: adminUid,
          updatedBy: adminUid,
          createdAt: now,
          updatedAt: now,
        },
        { merge: true },
      );
      await batch.commit();
    } else if (action === "save_ad_package") {
      const packageRef = cleanText(payload.packageId)
        ? db.collection("adPackages").doc(cleanText(payload.packageId))
        : db.collection("adPackages").doc();
      const creating = !cleanText(payload.packageId);
      await packageRef.set(
        {
          packageId: packageRef.id,
          nameAr: cleanText(payload.nameAr) || "باقة إعلان",
          nameEn: cleanText(payload.nameEn) || "Ad Package",
          descriptionAr: cleanText(payload.descriptionAr),
          descriptionEn: cleanText(payload.descriptionEn),
          durationDays: boundedInt(payload.durationDays, 7, 1, 90),
          maxImpressions: boundedInt(payload.maxImpressions, 1000, 100, 1000000),
          price: boundedInt(payload.price, 0, 0, 100000000),
          currency: cleanCurrency(payload.currency),
          active: payload.active !== false,
          sortOrder: boundedInt(payload.sortOrder, 100, -10000, 10000),
          updatedBy: adminUid,
          updatedAt: now,
          ...(creating ? { createdBy: adminUid, createdAt: now } : {}),
        },
        { merge: true },
      );
      result = { id: packageRef.id };
    } else if (action === "save_ad_payment_account") {
      const accountRef = cleanText(payload.accountId)
        ? db.collection("adPaymentAccounts").doc(cleanText(payload.accountId))
        : db.collection("adPaymentAccounts").doc();
      const creating = !cleanText(payload.accountId);
      await accountRef.set(
        {
          accountId: accountRef.id,
          nameAr: cleanText(payload.nameAr) || "وسيلة دفع",
          nameEn: cleanText(payload.nameEn) || "Payment method",
          type: cleanPaymentAccountType(payload.type),
          accountNumber: cleanText(payload.accountNumber),
          accountHolderName: cleanText(payload.accountHolderName),
          instructionsAr: cleanText(payload.instructionsAr),
          instructionsEn: cleanText(payload.instructionsEn),
          currency: cleanCurrency(payload.currency),
          active: payload.active !== false,
          sortOrder: boundedInt(payload.sortOrder, 100, -10000, 10000),
          updatedBy: adminUid,
          updatedAt: now,
          ...(creating ? { createdBy: adminUid, createdAt: now } : {}),
        },
        { merge: true },
      );
      result = { id: accountRef.id };
    } else if (
      [
        "approve_ad",
        "reject_ad",
        "pause_ad",
        "resume_ad",
        "approve_ad_payment",
        "reject_ad_payment",
      ].includes(action)
    ) {
      const adId = cleanText(payload.adId);
      if (!adId) {
        return res.status(400).json({ ok: false, error: "adId is required" });
      }

      const adRef = db.collection("ads").doc(adId);
      const adSnap = await adRef.get();
      if (!adSnap.exists) {
        return res.status(404).json({ ok: false, error: "Ad not found" });
      }

      const adData = adSnap.data() || {};
      const note = cleanText(payload.adminNote);
      let notificationType = "";
      let notificationText = "";

      if (action === "approve_ad") {
        await verifyAdMediaOwnership(adId, adData);
        const paid = cleanText(adData.paymentStatus).toLowerCase() === "paid";
        const days = boundedInt(adData.requestedDurationDays, 7, 1, 90);
        const start = Timestamp.now();
        const end = Timestamp.fromMillis(
          start.toMillis() + days * 24 * 60 * 60 * 1000,
        );
        await adRef.set(
          {
            status: paid ? "running" : "approved",
            reviewStatus: "approved",
            adminNote: note,
            reviewedBy: adminUid,
            reviewedAt: now,
            approvedAt: now,
            rejectedAt: null,
            startsAt: paid ? start : null,
            endsAt: paid ? end : null,
            completedAt: null,
            completionReason: "",
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = paid ? "ad_started" : "ad_approved";
        notificationText = paid
          ? "تمت الموافقة على إعلانك وبدأ بالظهور الآن."
          : "تمت الموافقة على إعلانك، وبانتظار تأكيد الدفع حتى يبدأ بالظهور.";
      } else if (action === "reject_ad") {
        if (!note) {
          return res.status(400).json({
            ok: false,
            error: "Rejection reason is required",
          });
        }
        await adRef.set(
          {
            status: "rejected",
            reviewStatus: "rejected",
            adminNote: note,
            reviewedBy: adminUid,
            reviewedAt: now,
            approvedAt: null,
            rejectedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = "ad_rejected";
        notificationText = `تم رفض إعلانك. السبب: ${note}`;
      } else if (action === "pause_ad") {
        await adRef.set(
          {
            status: "paused",
            adminNote: note,
            reviewedBy: adminUid,
            reviewedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = "ad_paused";
        notificationText = "تم إيقاف إعلانك مؤقتًا من الإدارة.";
      } else if (action === "resume_ad") {
        await verifyAdMediaOwnership(adId, adData);
        const paid = cleanText(adData.paymentStatus).toLowerCase() === "paid";
        await adRef.set(
          {
            status: paid ? "running" : "approved",
            reviewStatus: "approved",
            adminNote: note,
            reviewedBy: adminUid,
            reviewedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = paid ? "ad_started" : "ad_approved";
        notificationText = paid
          ? "تم تشغيل إعلانك مرة أخرى وبدأ بالظهور."
          : "تمت إعادة إعلانك للموافقة، وبانتظار تأكيد الدفع.";
      } else if (action === "approve_ad_payment") {
        await verifyAdMediaOwnership(adId, adData);
        const reviewStatus = cleanText(adData.reviewStatus).toLowerCase();
        const currentStatus = cleanText(adData.status).toLowerCase();
        const shouldStart =
          reviewStatus === "approved" &&
          ["approved", "pending_review"].includes(currentStatus);
        const days = boundedInt(adData.requestedDurationDays, 7, 1, 90);
        const start = Timestamp.now();
        const end = Timestamp.fromMillis(
          start.toMillis() + days * 24 * 60 * 60 * 1000,
        );
        await adRef.set(
          {
            paymentStatus: "paid",
            paidAmount: boundedInt(payload.paidAmount, 0, 0, 100000000),
            paymentAdminNote: note,
            paymentReviewedBy: adminUid,
            paymentReviewedAt: now,
            paidAt: now,
            ...(shouldStart
              ? { status: "running", startsAt: start, endsAt: end }
              : {}),
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = shouldStart ? "ad_started" : "ad_payment_approved";
        notificationText = shouldStart
          ? "تم تأكيد الدفع وبدأ إعلانك بالظهور الآن."
          : "تم تأكيد الدفع، وسيبدأ الإعلان بعد موافقة الإدارة.";
      } else if (action === "reject_ad_payment") {
        if (!note) {
          return res.status(400).json({
            ok: false,
            error: "Payment rejection reason is required",
          });
        }
        await adRef.set(
          {
            paymentStatus: "rejected_payment",
            paymentAdminNote: note,
            paymentReviewedBy: adminUid,
            paymentReviewedAt: now,
            updatedAt: now,
          },
          { merge: true },
        );
        notificationType = "ad_payment_rejected";
        notificationText = `تم رفض وصل الدفع. السبب: ${note}`;
      }

      await notifyAdOwner(
        adId,
        adminUid,
        notificationType,
        notificationText,
      );
    } else {
      return res.status(400).json({
        ok: false,
        error: "Unsupported admin action",
      });
    }

    await writeAdminLog(adminUid, action, payload, result);
    return res.json({ ok: true, ...result });
  } catch (error) {
    console.error("admin action error", action, error);
    return res.status(500).json({
      ok: false,
      error: error.message || "Server error",
    });
  }
});

app.get("/admin/stats", verifyUser, verifyAdmin, async (req, res) => {
  try {
    const now = Timestamp.now();

    const countResults = await Promise.all([
      safeCount("usersTotal", db.collection("users")),
      safeCount(
        "usersActive",
        db.collection("users").where("status", "==", "active"),
      ),
      safeCount(
        "usersBanned",
        db.collection("users").where("banned", "==", true),
      ),
      safeCount(
        "usersDeleted",
        db.collection("users").where("deleted", "==", true),
      ),
      safeCount("postsTotal", db.collection("posts")),
      safeCount(
        "postsImages",
        db.collection("posts").where("type", "==", "image"),
      ),
      safeCount(
        "postsReels",
        db.collection("posts").where("type", "==", "reel"),
      ),
      safeCount("storiesTotal", db.collection("stories")),
      safeCount(
        "storiesActive",
        db.collection("stories").where("expiresAt", ">", now),
      ),
      safeCount("conversationsTotal", db.collection("conversations")),
      safeCount("messagesTotal", db.collectionGroup("messages")),
      safeCount("callsTotal", db.collection("calls")),
      safeCount("adminLogsTotal", db.collection("adminLogs")),
    ]);

    const counts = {};
    const countErrors = {};

    countResults.forEach((item) => {
      counts[item.label] = item.value;
      if (item.error) countErrors[item.label] = item.error;
    });

    const [recentAdminLogs, media] = await Promise.all([
      getRecentAdminLogs(8),
      buildMediaSummary().catch((error) => ({
        error: error.message || "media-summary-failed",
      })),
    ]);

    return res.json({
      ok: true,
      generatedAt: new Date().toISOString(),
      counts,
      countErrors,
      media,
      recentAdminLogs,
      limitsNote:
        "This endpoint counts app data in Firestore. Firebase/Vercel/ImageKit plan limits must still be checked from each provider dashboard.",
    });
  } catch (error) {
    console.error("admin stats error", error);

    return res.status(500).json({
      ok: false,
      error: error.message || "Server error",
    });
  }
});

app.post("/admin/delete-user-completely", verifyUser, verifyAdmin, async (req, res) => {
  const startedAt = Date.now();

  try {
    const adminUid = req.user.uid;
    const targetUid = cleanText(req.body.targetUid || req.body.uid);
    const reason = cleanText(req.body.reason);
    const confirm = cleanText(req.body.confirm);

    if (!targetUid) {
      return res.status(400).json({
        ok: false,
        error: "targetUid is required",
      });
    }

    if (targetUid === adminUid) {
      return res.status(400).json({
        ok: false,
        error: "Admin cannot delete own account",
      });
    }

    if (confirm !== "DELETE") {
      return res.status(400).json({
        ok: false,
        error: "DELETE confirmation is required",
      });
    }

    const targetUserRef = db.collection("users").doc(targetUid);

    await db.collection("adminLogs").doc().set({
      action: "delete_user_completely_started",
      adminUid,
      targetUid,
      reason,
      createdAt: FieldValue.serverTimestamp(),
    });

    await targetUserRef
      .set(
        {
          uid: targetUid,
          status: "deleting",
          deleted: true,
          isDeleted: true,
          canMessage: false,
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      )
      .catch(() => {});

    const posts = await deleteUserPostsCompletely(targetUid);
    const stories = await deleteUserStoriesCompletely(targetUid);
    const conversations = await deleteUserConversationsCompletely(targetUid);
    const reactions = await deleteUserReactionsEverywhere(targetUid);
    const references = await deleteUserReferencesEverywhere(targetUid);
    const calls = await deleteUserCallsCompletely(targetUid);
    const userSubcollections = await deleteUserRootSubcollections(targetUid);

    await targetUserRef.delete().catch((error) => {
      console.warn(
        "Failed to delete user firestore doc",
        targetUid,
        error.message,
      );
    });

    let authDeleted = false;
    let authDeleteSkipped = false;

    try {
      await getAuth().deleteUser(targetUid);
      authDeleted = true;
    } catch (error) {
      if (error.code === "auth/user-not-found") {
        authDeleteSkipped = true;
      } else {
        throw error;
      }
    }

    const result = {
      ok: true,
      deleted: true,
      targetUid,
      authDeleted,
      authDeleteSkipped,
      durationMs: Date.now() - startedAt,
      posts,
      stories,
      conversations,
      reactions,
      references,
      calls,
      userSubcollections,
    };

    await db.collection("adminLogs").doc().set({
      action: "delete_user_completely_finished",
      adminUid,
      targetUid,
      reason,
      result,
      createdAt: FieldValue.serverTimestamp(),
    });

    return res.json(result);
  } catch (error) {
    console.error("admin delete-user-completely error", error);

    return res.status(500).json({
      ok: false,
      error: error.message || "Server error",
    });
  }
});

app.post(
  "/delete-imagekit-file",
  verifyUser,
  secureAction("delete_imagekit_file", 20, 3600, { messaging: false }),
  async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const fileId = cleanText(req.body.fileId);

    if (!isSafeDocumentId(fileId)) {
      return res.status(400).json({
        ok: false,
        error: "A valid fileId is required",
      });
    }

    const ownsFile = await userOwnsImageKitFile(actorUid, fileId);
    const adminUser = await isAdminUser(req.user.uid, req.user.email);
    if (!ownsFile && !adminUser) {
      return res.status(403).json({
        ok: false,
        error: "File ownership could not be verified",
      });
    }

    const result = await deleteImageKitFile(fileId);
    await db.collection("_mediaAssets").doc(fileId).set(
      {
        status: "deleted",
        deletedBy: actorUid,
        deletedAt: FieldValue.serverTimestamp(),
      },
      { merge: true },
    );

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("delete-imagekit-file error", error);

    return res.status(500).json({
      ok: false,
      error: "Server error",
      requestId: req.requestId,
    });
  }
},
);

app.post("/delete-post", verifyUser, async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);

    if (!postId) {
      return res.status(400).json({
        ok: false,
        error: "postId is required",
      });
    }

    const postRef = db.collection("posts").doc(postId);
    const postSnap = await postRef.get();

    if (!postSnap.exists) {
      return res.json({
        ok: true,
        deleted: false,
        reason: "post-not-found",
      });
    }

    const postData = postSnap.data() || {};
    const ownerUid = cleanText(postData.userId);

    if (!ownerUid || actorUid !== ownerUid) {
      return res.status(403).json({
        ok: false,
        error: "Permission denied",
      });
    }

    const fileIds = imageKitFileIdsFromPost(postData);
    const subDeletes = await deletePostSubcollections(postRef);

    const batch = db.batch();

    batch.delete(postRef);

    batch.update(db.collection("users").doc(ownerUid), {
      postsCount: FieldValue.increment(-1),
    });

    await batch.commit();

    const deletedSavedPosts = await deleteQueryBatch(
      db.collectionGroup("savedPosts").where("postId", "==", postId),
      300,
    ).catch((error) => {
      console.warn(
        "Failed to delete savedPosts for post",
        postId,
        error.message,
      );
      return 0;
    });

    const deletedNotifications = await deleteQueryBatch(
      db.collectionGroup("notifications").where("postId", "==", postId),
      300,
    ).catch((error) => {
      console.warn(
        "Failed to delete notifications for post",
        postId,
        error.message,
      );
      return 0;
    });

    const mediaDeletes = await deleteImageKitFiles(fileIds);

    return res.json({
      ok: true,
      deleted: true,
      postId,
      deletedSavedPosts,
      deletedNotifications,
      mediaDeletes,
      ...subDeletes,
    });
  } catch (error) {
    console.error("delete-post error", error);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);

  const status = Number(error.statusCode || error.status || 500);
  const safeStatus = status >= 400 && status < 600 ? status : 500;
  console.error("request failed", {
    requestId: req.requestId,
    method: req.method,
    path: req.path,
    status: safeStatus,
    code: cleanText(error.code),
    message: shortText(error.message, 160),
  });

  return res.status(safeStatus).json({
    ok: false,
    error:
      safeStatus === 403
        ? "Request is not allowed"
        : safeStatus === 413
          ? "Request body is too large"
          : "Server error",
    requestId: req.requestId,
  });
});

const port = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(port, () => {
    console.log(`MONO notification server running on port ${port}`);
  });
}

module.exports = app;
