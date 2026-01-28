// controllers/certificateController.js
import Certificate from "../models/certificateModel.js";
import mongoose from "mongoose";

const isValidId = (id) => mongoose.Types.ObjectId.isValid(id);

// Create new certificate
export const createCertificate = async (req, res) => {
  try {
    const { empID, empName } = req.body;
    if (!empID || !empName) return res.status(400).json({ success: false, message: "All fields required" });

    // Check if empID already exists
    const existing = await Certificate.findOne({ empID });
    if (existing) return res.status(400).json({ success: false, message: "Employee ID already exists" });

    const cert = new Certificate({ empID, empName });
    const saved = await cert.save();
    res.status(201).json({ success: true, data: saved });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// Get all certificates
export const getCertificates = async (req, res) => {
  try {
    const certificates = await Certificate.find();
    res.status(200).json({ success: true, data: certificates });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// Get certificate by ID
export const getCertificateById = async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ success: false, message: "Invalid ID" });

    const cert = await Certificate.findById(id);
    if (!cert) return res.status(404).json({ success: false, message: "Certificate not found" });

    res.status(200).json({ success: true, data: cert });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// Update certificate
export const updateCertificate = async (req, res) => {
  try {
    const { id } = req.params;
    const { empID, empName } = req.body;

    if (!isValidId(id)) return res.status(400).json({ success: false, message: "Invalid ID" });
    if (!empID || !empName) return res.status(400).json({ success: false, message: "All fields required" });

    const updated = await Certificate.findByIdAndUpdate(
      id,
      { empID, empName },
      { new: true, runValidators: true }
    );

    if (!updated) return res.status(404).json({ success: false, message: "Certificate not found" });

    res.status(200).json({ success: true, data: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// Delete certificate
export const deleteCertificate = async (req, res) => {
  try {
    const { id } = req.params;
    if (!isValidId(id)) return res.status(400).json({ success: false, message: "Invalid ID" });

    const deleted = await Certificate.findByIdAndDelete(id);
    if (!deleted) return res.status(404).json({ success: false, message: "Certificate not found" });

    res.status(200).json({ success: true, message: "Certificate deleted successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};
