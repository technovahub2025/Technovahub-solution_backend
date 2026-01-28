// routes/adminRoutes.js
import express from "express";
import { loginAdmin, logoutAdmin, registerAdmin } from "../controllers/authController.js";

const router = express.Router();




router.post("/register", registerAdmin);
router.post("/login", loginAdmin);

router.post("/logout", logoutAdmin)

export default router;
