import dotenv from "dotenv";
import { google } from "googleapis";

dotenv.config({
  path: process.env.NODE_ENV === "production" ? ".env.production" : ".env.local",
});
dotenv.config();

const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_REDIRECT_URI,
} = process.env;

const clientId = GOOGLE_CLIENT_ID || process.env.GOOGLE_DRIVE_CLIENT_ID;
const clientSecret = GOOGLE_CLIENT_SECRET || process.env.GOOGLE_DRIVE_CLIENT_SECRET;
const redirectUri = GOOGLE_REDIRECT_URI || process.env.GOOGLE_DRIVE_REDIRECT_URI;

if (!clientId || !clientSecret || !redirectUri) {
  throw new Error("Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI");
}

const auth = new google.auth.OAuth2(
  clientId,
  clientSecret,
  redirectUri
);
const code = process.argv[2];

if (!code) {
  console.log("Open this URL in a browser and approve access:");
  console.log(
    auth.generateAuthUrl({
      access_type: "offline",
      prompt: "consent",
      scope: ["https://www.googleapis.com/auth/drive.file"],
    })
  );
  console.log("\nThen run: npm run google-drive-auth -- <authorization-code>");
} else {
  const { tokens } = await auth.getToken(code);
  console.log("GOOGLE_DRIVE_REFRESH_TOKEN=");
  console.log(tokens.refresh_token || "No refresh token returned. Revoke access and retry.");
}
