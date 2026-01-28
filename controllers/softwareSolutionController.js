import Software from "../models/softwareSolutionModel.js";
import mongoose from "mongoose";

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id);

// Create a new course
export const createSolution = async (req, res) => {
    try {
        const { title, description } = req.body;

        if (!title || !description) {
            return res.status(400).json({ success: false, message: "Title and description are required" });
        }

        const software = new Software({ title, description });
        const savedSoftware = await software.save();

        res.status(201).json({ success: true, data: savedSoftware });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Get all courses
export const getSoftware = async (req, res) => {
    try {
        const software = await Software.find();
        res.status(200).json({ success: true, data: software });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Get a single course by ID
export const getSoftwareById = async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        const software = await Software.findById(id);
        if (!course) return res.status(404).json({ success: false, message: "Course not found" });

        res.status(200).json({ success: true, data: software });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Update a course by ID
export const updateSoftware = async (req, res) => {
    try {
        const { id } = req.params;
        const { title, description } = req.body;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        if (!title || !description) {
            return res.status(400).json({ success: false, message: "Title and description are required" });
        }

        const updatedSoftware = await Software.findByIdAndUpdate(
            id,
            { title, description },
            { new: true, runValidators: true }
        );

        if (!updatedSoftware) return res.status(404).json({ success: false, message: "Course not found" });

        res.status(200).json({ success: true, data: updatedSoftware });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};

// Delete a course by ID
export const deleteSoftware = async (req, res) => {
    try {
        const { id } = req.params;

        if (!isValidId(id)) {
            return res.status(400).json({ success: false, message: "Invalid course ID" });
        }

        const deletedSoftware = await Software.findByIdAndDelete(id);
        if (!deletedSoftware) return res.status(404).json({ success: false, message: "Software solution  not found" });

        res.status(200).json({ success: true, message: "Software solution deleted successfully" });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message });
    }
};
