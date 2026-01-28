import express from "express";

import { createSolution, deleteSoftware, getSoftware, getSoftwareById, updateSoftware } from "../controllers/softwareSolutionController.js";

const router = express.Router();

// CRUD routes
router.post("/", createSolution);           // Create
router.get("/", getSoftware);             // Read all
router.get("/:id", getSoftwareById);       // Read one
router.put("/:id", updateSoftware);        // Update
router.delete("/:id", deleteSoftware);     // Delete

export default router;
