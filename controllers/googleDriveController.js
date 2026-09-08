import jwt from "jsonwebtoken";
import { exchangeGoogleDriveCode, getGoogleDriveAuthorizationUrl } from "../config/googleDrive.js";

const getFrontendUrl = () =>
  (process.env.FRONTEND_URL || "http://localhost:5173").replace(/\/$/, "");

export const connectGoogleDrive = (req, res) => {
  const state = jwt.sign({ adminId: req.admin._id.toString() }, process.env.JWT_SECRET, { expiresIn: "10m" });
  res.json({ authorizationUrl: getGoogleDriveAuthorizationUrl(state) });
};

export const googleDriveCallback = async (req, res) => {
  try {
    const { code, state, error } = req.query;
    if (error) throw new Error(`Google authorization failed: ${error}`);
    if (!code || !state) throw new Error("Missing Google authorization code or state");
    jwt.verify(state, process.env.JWT_SECRET);
    await exchangeGoogleDriveCode(code);
    res.redirect(`${getFrontendUrl()}/admin/gallery?googleDrive=connected`);
  } catch (error) {
    const message = encodeURIComponent(error.message || "Google Drive connection failed");
    res.redirect(`${getFrontendUrl()}/admin/gallery?googleDrive=error&message=${message}`);
  }
};
