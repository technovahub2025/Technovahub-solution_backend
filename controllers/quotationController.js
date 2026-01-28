import Quatation from "../models/quatationModel.js";

// Get all quotations
export const getAllQuotations = async (req, res) => {
  try {
    const quotations = await Quatation.find().sort({ createdAt: -1 });
    res.status(200).json(quotations);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};

// Get a single quotation by ID
export const getQuotationById = async (req, res) => {
  try {
    const quotation = await Quatation.findById(req.params.id);
    if (!quotation) {
      return res.status(404).json({ message: "Quotation not found" });
    }
    res.status(200).json(quotation);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};

// Create a new quotation
export const createQuotation = async (req, res) => {
  try {
    const newQuotation = new Quatation(req.body);
    const savedQuotation = await newQuotation.save();
    res.status(201).json(savedQuotation);
  } catch (error) {
    res.status(400).json({ message: "Invalid data", error: error.message });
  }
};

// Update a quotation by ID
export const updateQuotation = async (req, res) => {
  try {
    const updatedQuotation = await Quatation.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true, runValidators: true }
    );
    if (!updatedQuotation) {
      return res.status(404).json({ message: "Quotation not found" });
    }
    res.status(200).json(updatedQuotation);
  } catch (error) {
    res.status(400).json({ message: "Invalid data", error: error.message });
  }
};

// Delete a quotation by ID
export const deleteQuotation = async (req, res) => {
  try {
    const deletedQuotation = await Quatation.findByIdAndDelete(req.params.id);
    if (!deletedQuotation) {
      return res.status(404).json({ message: "Quotation not found" });
    }
    res.status(200).json({ message: "Quotation deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};
