import SalarySlip from "../models/salaryModel.js";

// 🧾 Create a new salary slip
export const createSalarySlip = async (req, res) => {
  try {
    const slip = await SalarySlip.create(req.body);
    res.status(201).json({ success: true, message: "Salary slip created", data: slip });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// 📋 Get all salary slips
export const getAllSlips = async (req, res) => {
  try {
    const slips = await SalarySlip.find().sort({ createdAt: -1 });
    res.status(200).json({ success: true, data: slips });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// 🔍 Get single slip by ID
export const getSlipById = async (req, res) => {
  try {
    const slip = await SalarySlip.findById(req.params.id);
    if (!slip) return res.status(404).json({ success: false, message: "Salary slip not found" });
    res.status(200).json({ success: true, data: slip });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// ✏️ Update a salary slip
export const updateSalarySlip = async (req, res) => {
  try {
    const slip = await SalarySlip.findOneAndUpdate(
      { _id: req.params.id },
      req.body,
      { new: true, runValidators: true }
    );
    if (!slip) return res.status(404).json({ success: false, message: "Salary slip not found" });
    res.status(200).json({ success: true, message: "Salary slip updated", data: slip });
  } catch (error) {
    res.status(400).json({ success: false, message: error.message });
  }
};

// 🗑️ Delete a salary slip
export const deleteSalarySlip = async (req, res) => {
  try {
    const slip = await SalarySlip.findByIdAndDelete(req.params.id);
    if (!slip) return res.status(404).json({ success: false, message: "Salary slip not found" });
    res.status(200).json({ success: true, message: "Salary slip deleted" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};
