import express from "express";
import { loginAdmin, logoutAdmin, registerAdmin } from "../controllers/authController.js";
import { connectGoogleDrive, googleDriveCallback, googleDriveStatus } from "../controllers/googleDriveController.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/register", registerAdmin);
router.post("/login", loginAdmin);
router.post("/logout", logoutAdmin);

router.get("/google-drive/status", protect, googleDriveStatus);

router.get("/google-drive/connect", (req, res, next) => {
  console.log("[auth] Google Drive connect route matched; running auth protection");
  next();
}, protect, connectGoogleDrive);
router.get("/google-drive/callback", (req, res, next) => {
  console.log("[auth] Google Drive callback route hit");
  next();
}, googleDriveCallback);

export default router;
