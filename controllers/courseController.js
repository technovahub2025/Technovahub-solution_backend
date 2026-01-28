import Course from "../models/courseModels.js";
import mongoose from "mongoose";

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id);

// Create a new course
export const createCourse = async (req, res) => {
    try {
        const { title, description } = req.body;

        if (!title || !description) {
            return res.status(400).json({ success: false, message: "Title and description are required" });
        }

        const course = new Course({ title, description });
        const savedCourse = await course.save();

        res.status(201).json({ success: true, data: savedCourse });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Get all courses
export const getCourses = async (req, res) => {
    try {
        const courses = await Course.find();
        res.status(200).json({ success: true, data: courses });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Get a single course by ID
export const getCourseById = async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        const course = await Course.findById(id);
        if (!course) return res.status(404).json({ success: false, message: "Course not found" });

        res.status(200).json({ success: true, data: course });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Update a course by ID
export const updateCourse = async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description } = req.body;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        if (!title || !description) {
            return res.status(400).json({ success: false, message: "Title and description are required" });
        }

        const updatedCourse = await Course.findByIdAndUpdate(
            id,
            { title, description },
            { new: true, runValidators: true }
        );

        if (!updatedCourse) return res.status(404).json({ success: false, message: "Course not found" });

        res.status(200).json({ success: true, data: updatedCourse });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Delete a course by ID
export const deleteCourse = async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        const deletedCourse = await Course.findByIdAndDelete(id);
        if (!deletedCourse) return res.status(404).json({ success: false, message: "Course not found" });

        res.status(200).json({ success: true, message: "Course deleted successfully" });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};
