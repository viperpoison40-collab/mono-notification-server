require("dotenv").config();

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const { createHmac, randomBytes } = require("crypto");

const app = express();

app.use(cors());
app.use(express.json({ limit: "1mb" }));

const serviceAccount = process.env.FIREBASE_PRIVATE_KEY
  ? {
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }
  : require("./serviceAccountKey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

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

    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
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

    return data.isAdmin === true || role === "admin" || role === "owner";
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

  const response = await admin.messaging().sendEachForMulticast({
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

  const response = await admin.messaging().sendEachForMulticast({
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
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
          likesCount: admin.firestore.FieldValue.increment(-1),
        });
        deletedPostLikes += 1;
      } else if (parentCollection === "comments") {
        batch.update(likedParentRef, {
          likesCount: admin.firestore.FieldValue.increment(-1),
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
          commentsCount: admin.firestore.FieldValue.increment(-1),
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
  const privateKey = getImageKitPrivateKey();

  return res.json({
    ok: true,
    hasPrivateKey: Boolean(privateKey),
    privateKeyLooksValid: privateKey.startsWith("private_"),
    privateKeyPreview: maskSecret(privateKey),
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

function maskSecret(value) {
  const text = cleanText(value);
  if (!text) return "";
  if (text.length <= 10) return "***";
  return `${text.substring(0, 8)}...${text.substring(text.length - 4)}`;
}

app.get("/imagekit-upload-auth", verifyUser, async (req, res) => {
  try {
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
      console.error("ImageKit upload auth failed: invalid private key format", {
        privateKeyPreview: maskSecret(privateKey),
      });

      return res.status(503).json({
        ok: false,
        code: "invalid_imagekit_private_key",
        error:
          "IMAGEKIT_PRIVATE_KEY exists but does not look like an ImageKit private key.",
      });
    }

    const token = randomBytes(24).toString("hex");
    const expire = Math.floor(Date.now() / 1000) + 10 * 60;

    const signature = createHmac("sha1", privateKey)
      .update(`${token}${expire}`)
      .digest("hex");

    return res.json({
      ok: true,
      token,
      expire,
      signature,
    });
  } catch (error) {
    console.error("imagekit-upload-auth error", error);

    return res.status(500).json({
      ok: false,
      code: "imagekit_upload_auth_failed",
      error: error.message || "Server error",
    });
  }
});
app.post("/send-message", verifyUser, async (req, res) => {
  try {
    const senderUid = req.user.uid;
    const toUid = cleanText(req.body.toUid);
    const convoId = cleanText(req.body.convoId);
    const messageId = cleanText(req.body.messageId);
    const text = cleanText(req.body.text);

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

    const senderName = await getUserTitle(senderUid);

    const result = await sendPushToUser({
      uid: toUid,
      title: senderName,
      body: shortText(text, 100) || "أرسل لك رسالة جديدة",
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
    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});

app.post("/send-call", verifyUser, async (req, res) => {
  try {
    const callerUid = req.user.uid;
    const receiverUid = cleanText(req.body.receiverUid);
    const callId = cleanText(req.body.callId);
    const conversationId = cleanText(
      req.body.conversationId || req.body.convoId,
    );

    const callType = cleanText(req.body.callType) === "video" ? "video" : "voice";

    if (!receiverUid || !callId) {
      return res.status(400).json({
        ok: false,
        error: "receiverUid and callId are required",
      });
    }

    if (receiverUid === callerUid) {
      return res.status(400).json({
        ok: false,
        error: "Cannot call yourself",
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
    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});

app.post("/send-notification", verifyUser, async (req, res) => {
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
    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});

app.post("/toggle-like", verifyUser, async (req, res) => {
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
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });
        likesCount += 1;
        liked = true;
      }

      tx.update(postRef, {
        likesCount,
        trendScore: trendScore(likesCount, commentsCount),
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
});

app.post("/add-comment", verifyUser, async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const text = cleanText(req.body.text);
    const actorUsernameFallback = cleanText(req.body.actorUsername);

    if (!postId || !text) {
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
      username: actorUsernameFallback || "user",
      avatarUrl: "",
    }));

    if (actorUsernameFallback) actor.username = actorUsernameFallback;

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
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        likesCount: 0,
      });

      tx.update(postRef, {
        commentsCount,
        trendScore: trendScore(likesCount, commentsCount),
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
});

app.post("/delete-comment", verifyUser, async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const commentId = cleanText(req.body.commentId);

    if (!postId || !commentId) {
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
});

app.post("/toggle-comment-like", verifyUser, async (req, res) => {
  try {
    const actorUid = req.user.uid;
    const postId = cleanText(req.body.postId);
    const commentId = cleanText(req.body.commentId);

    if (!postId || !commentId) {
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
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
});

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
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
        });

        tx.set(followingRef, {
          uid: otherUid,
          createdAt: admin.firestore.FieldValue.serverTimestamp(),
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
app.get("/admin/stats", verifyUser, verifyAdmin, async (req, res) => {
  try {
    const now = admin.firestore.Timestamp.now();

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
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
    });

    await targetUserRef
      .set(
        {
          uid: targetUid,
          status: "deleting",
          deleted: true,
          isDeleted: true,
          canMessage: false,
          updatedAt: admin.firestore.FieldValue.serverTimestamp(),
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
      await admin.auth().deleteUser(targetUid);
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
      createdAt: admin.firestore.FieldValue.serverTimestamp(),
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

app.post("/delete-imagekit-file", verifyUser, async (req, res) => {
  try {
    const fileId = cleanText(req.body.fileId);

    if (!fileId) {
      return res.status(400).json({
        ok: false,
        error: "fileId is required",
      });
    }

    const result = await deleteImageKitFile(fileId);

    return res.json({
      ok: true,
      ...result,
    });
  } catch (error) {
    console.error("delete-imagekit-file error", error);

    return res.status(500).json({
      ok: false,
      error: "Server error",
    });
  }
});

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
      postsCount: admin.firestore.FieldValue.increment(-1),
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

const port = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(port, () => {
    console.log(`MONO notification server running on port ${port}`);
  });
}

module.exports = app;