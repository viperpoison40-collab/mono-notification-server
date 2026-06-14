# MONO Notification Server

سيرفر صغير لإرسال Push Notifications لتطبيق MONO بدون Firebase Cloud Functions.

## الفكرة

Flutter يكتب الرسالة أو المكالمة في Firestore، ثم يستدعي هذا السيرفر:

- `POST /send-message`
- `POST /send-call`
- `POST /send-notification`

السيرفر يتحقق من Firebase ID Token ثم يرسل FCM للطرف الثاني.

## التشغيل محليًا

```powershell
cd C:\Users\Ahmed\mono-notification-server
npm install
copy .env.example .env
npm start
```

## الرفع على Render

1. ارفع هذا المجلد على GitHub.
2. في Render اختر New Web Service.
3. اربط مستودع GitHub.
4. Build Command:
   ```bash
   npm install
   ```
5. Start Command:
   ```bash
   npm start
   ```
6. Environment Variables:
   - `FIREBASE_PROJECT_ID`
   - `FIREBASE_CLIENT_EMAIL`
   - `FIREBASE_PRIVATE_KEY`

## مهم جدًا

لا ترفع ملف `.env` إلى GitHub.
لا تشارك private key مع أي شخص.
