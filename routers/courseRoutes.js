import express from "express";
import {
    createCourse,
    getCourses,
    getCourseById,
    updateCourse,
    deleteCourse
} from "../controllers/courseController.js";
// import { protect } from "../middleware/authMiddleware.js";

const router = express.Router();

// CRUD routes
router.post("/", createCourse);           // Create
router.get("/", getCourses);             // Read all
router.get("/:id", getCourseById);       // Read one
router.put("/:id", updateCourse);        // Update
router.delete("/:id", deleteCourse);     // Delete

export default router;
