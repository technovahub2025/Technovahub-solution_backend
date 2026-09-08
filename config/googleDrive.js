import dotenv from "dotenv";
import crypto from "crypto";
import { google } from "googleapis";
import GoogleDriveToken from "../models/GoogleDriveToken.js";

const envFile = process.env.NODE_ENV === "production" ? ".env.production" : ".env.local";
dotenv.config({ path: envFile });
dotenv.config();

const clientId = process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_DRIVE_CLIENT_ID;
const clientSecret = process.env.GOOGLE_CLIENT_SECRET || process.env.GOOGLE_DRIVE_CLIENT_SECRET;
const redirectUri = process.env.GOOGLE_REDIRECT_URI || process.env.GOOGLE_DRIVE_REDIRECT_URI;

if (!clientId || !clientSecret || !redirectUri) {
  throw new Error(
    "Set GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, and GOOGLE_REDIRECT_URI in the environment"
  );
}

console.log(`[google-drive] OAuth config loaded: redirectUri=${redirectUri}`);

const scopes = ["https://www.googleapis.com/auth/drive.file"];

const createOAuthClient = () => new google.auth.OAuth2(clientId, clientSecret, redirectUri);

const getEncryptionKey = () => {
  const key =
    process.env.GOOGLE_REFRESH_TOKEN_ENCRYPTION_KEY ||
    process.env.GOOGLE_TOKEN_ENCRYPTION_KEY ||
    process.env.JWT_SECRET;

  if (!key) {
    throw new Error("Set GOOGLE_REFRESH_TOKEN_ENCRYPTION_KEY for secure Google Drive token storage");
  }

  return crypto.createHash("sha256").update(String(key)).digest();
};

const encrypt = (value) => {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", getEncryptionKey(), iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);

  return [iv.toString("hex"), cipher.getAuthTag().toString("hex"), encrypted.toString("hex")].join(
    ":"
  );
};

const decrypt = (value) => {
  const [ivHex, authTagHex, encryptedHex] = value.split(":");
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    getEncryptionKey(),
    Buffer.from(ivHex, "hex")
  );
  decipher.setAuthTag(Buffer.from(authTagHex, "hex"));

  return Buffer.concat([
    decipher.update(Buffer.from(encryptedHex, "hex")),
    decipher.final(),
  ]).toString("utf8");
};

export const getGoogleDriveAuthorizationUrl = (state) =>
  createOAuthClient().generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: scopes,
    state,
  });

export const saveGoogleDriveRefreshToken = async (refreshToken) => {
  await GoogleDriveToken.findOneAndUpdate(
    { provider: "google-drive" },
    { encryptedRefreshToken: encrypt(refreshToken) },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );
  console.log("[google-drive] Refresh token encrypted and stored");
};

const getRefreshToken = async () => {
  if (process.env.GOOGLE_REFRESH_TOKEN) {
    return process.env.GOOGLE_REFRESH_TOKEN;
  }

  const token = await GoogleDriveToken.findOne({ provider: "google-drive" });
  return token ? decrypt(token.encryptedRefreshToken) : null;
};

export const exchangeGoogleDriveCode = async (code) => {
  const { tokens } = await createOAuthClient().getToken(code);

  if (tokens.refresh_token) {
    await saveGoogleDriveRefreshToken(tokens.refresh_token);
  }

  return tokens;
};

export const getDriveClient = async () => {
  const refreshToken = await getRefreshToken();

  if (!refreshToken) {
    throw new Error("Connect Google Drive before uploading images");
  }

  const auth = createOAuthClient();
  auth.setCredentials({ refresh_token: refreshToken });

  return google.drive({ version: "v3", auth });
};
