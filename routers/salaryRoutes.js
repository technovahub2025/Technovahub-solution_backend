import express from "express";
import {
  createSalarySlip,
  getAllSlips,
  getSlipById,
  updateSalarySlip,
  deleteSalarySlip,
} from "../controllers/salaryController.js";

const router = express.Router();

// CRUD Routes
router.post("/", createSalarySlip);      // Create
router.get("/", getAllSlips);            // Read all
router.get("/:id", getSlipById);         // Read one
router.put("/:id", updateSalarySlip);    // Update
router.delete("/:id", deleteSalarySlip); // Delete

export default router;
