import jwt from "jsonwebtoken";
import { exchangeGoogleDriveCode, getGoogleDriveAuthorizationUrl, getGoogleDriveConnectionStatus } from "../config/googleDrive.js";

const getFrontendUrl = () =>
  (process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/$/, "");

export const googleDriveStatus = async (req, res) => {
  res.set("Cache-Control", "no-store");
  if (!req.admin?._id) {
    return res.status(401).json({ success: false, message: "Not authorized" });
  }

  try {
    const status = await getGoogleDriveConnectionStatus();
    return res.json({ success: true, ...status });
  } catch (error) {
    console.error("[google-drive] Status check failed");
    return res.status(500).json({
      success: false,
      message: "Unable to check Google Drive connection",
    });
  }
};

export const connectGoogleDrive = (req, res) => {
  if (!req.admin?._id) {
    console.warn("[google-drive] Connect rejected: authenticated admin was not found");
    return res.status(401).json({ success: false, message: "Not authorized" });
  }

  try {
    const state = jwt.sign(
      { adminId: req.admin._id.toString() },
      process.env.JWT_SECRET,
      { expiresIn: "10m" }
    );
    const authUrl = getGoogleDriveAuthorizationUrl(state);
    console.log(`[google-drive] Authorization URL generated for admin=${req.admin._id}`);

    return res.json({
      success: true,
      authUrl,
      authorizationUrl: authUrl,
    });
  } catch (error) {
    console.error(`[google-drive] Connect failed: ${error.message}`);
    return res.status(error.statusCode || 500).json({
      success: false,
      message: error.statusCode === 503 ? error.message : "Google Drive connection failed",
    });
  }
};

export const googleDriveCallback = async (req, res) => {
  try {
    const { code, state, error } = req.query;
    console.log(
      `[google-drive] Callback received: code=${Boolean(code)} state=${Boolean(state)} error=${
        error || "none"
      }`
    );
    if (error) throw new Error(`Google authorization failed: ${error}`);
    if (!code || !state) throw new Error("Missing Google authorization code or state");

    jwt.verify(state, process.env.JWT_SECRET);
    const tokens = await exchangeGoogleDriveCode(code);
    console.log(`[google-drive] OAuth exchange completed; refreshToken=${Boolean(tokens.refresh_token)}`);
    res.redirect(`${getFrontendUrl()}/admin/gallery?googleDrive=connected`);
  } catch (error) {
    console.error(`[google-drive] Callback failed: ${error.message}`);
    const message = encodeURIComponent(error.message || "Google Drive connection failed");
    res.redirect(`${getFrontendUrl()}/admin/gallery?googleDrive=error&message=${message}`);
  }
};
