import express from "express";
import { loginAdmin, logoutAdmin, registerAdmin } from "../controllers/authController.js";
import { connectGoogleDrive, googleDriveCallback } from "../controllers/googleDriveController.js";
import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/register", registerAdmin);
router.post("/login", loginAdmin);
router.post("/logout", logoutAdmin);

router.get("/google-drive/connect", protect, connectGoogleDrive);
router.get("/google-drive/callback", googleDriveCallback);

export default router;
