require("dotenv").config();

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

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

async function verifyUser(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.substring("Bearer ".length)
      : "";

    if (!token) {
      return res.status(401).json({ ok: false, error: "Missing Firebase ID token" });
    }

    const decoded = await admin.auth().verifyIdToken(token);
    req.user = decoded;
    return next();
  } catch (error) {
    return res.status(401).json({ ok: false, error: "Invalid Firebase ID token" });
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
    if (username) return username;
  } catch (error) {
    console.warn("Failed to read user title", uid, error.message);
  }

  return "MONO";
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

async function deleteBadTokens(uid, badTokens) {
  if (!uid || badTokens.length === 0) return;

  const batch = db.batch();

  badTokens.forEach((token) => {
    const ref = db
      .collection("users")
      .doc(uid)
      .collection("fcmTokens")
      .doc(token);

    batch.delete(ref);
  });

  await batch.commit();
}

async function sendPushToUser({ uid, title, body, data = {} }) {
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
    notification: {
      title,
      body,
    },
    data,
    android: {
      priority: "high",
      notification: {
        channelId: "mono_default_channel",
        sound: "default",
        priority: "high",
        defaultSound: true,
        defaultVibrateTimings: true,
      },
    },
  });

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

  await deleteBadTokens(uid, badTokens);

  return {
    ok: true,
    sent: response.successCount,
    failed: response.failureCount,
    deletedBadTokens: badTokens.length,
  };
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
    const shortText = text.length > 120 ? `${text.substring(0, 120)}...` : text;

    const result = await sendPushToUser({
      uid: toUid,
      title: `رسالة جديدة من ${senderName}`,
      body: shortText || "أرسل لك رسالة",
      data: {
        type: "message",
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
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/send-call", verifyUser, async (req, res) => {
  try {
    const callerUid = req.user.uid;

    const receiverUid = cleanText(req.body.receiverUid);
    const callId = cleanText(req.body.callId);
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

    const callerName = await getUserTitle(callerUid);

    const result = await sendPushToUser({
      uid: receiverUid,
      title: callType === "video" ? "مكالمة فيديو واردة" : "مكالمة صوتية واردة",
      body: `${callerName} يتصل بك الآن`,
      data: {
        type: "call",
        callId,
        callerUid,
        receiverUid,
        callType,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });

    return res.json(result);
  } catch (error) {
    console.error("send-call error", error);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

app.post("/send-notification", verifyUser, async (req, res) => {
  try {
    const fromUid = req.user.uid;

    const toUid = cleanText(req.body.toUid);
    const notificationId = cleanText(req.body.notificationId);
    const notificationType = cleanText(req.body.notificationType);
    const fallbackText = cleanText(req.body.text);

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

    let title = "إشعار جديد";
    let body = fallbackText || "لديك إشعار جديد";

    if (notificationType === "like") {
      title = "إعجاب جديد";
      body = `${fromName} أعجب بمنشورك`;
    } else if (notificationType === "comment") {
      title = "تعليق جديد";
      body = `${fromName} علّق على منشورك`;
    } else if (notificationType === "follow") {
      title = "متابع جديد";
      body = `${fromName} بدأ بمتابعتك`;
    }

    const result = await sendPushToUser({
      uid: toUid,
      title,
      body,
      data: {
        type: "notification",
        notificationId,
        fromUid,
        toUid,
        notificationType,
        click_action: "FLUTTER_NOTIFICATION_CLICK",
      },
    });

    return res.json(result);
  } catch (error) {
    console.error("send-notification error", error);
    return res.status(500).json({ ok: false, error: "Server error" });
  }
});

const port = process.env.PORT || 3000;

if (require.main === module) {
  app.listen(port, () => {
    console.log(`MONO notification server running on port ${port}`);
  });
}

module.exports = app;