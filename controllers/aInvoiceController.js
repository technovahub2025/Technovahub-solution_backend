import AnInvoice from "../models/arounInvoiceModel.js";


export const getAllAInvoice = async (req, res) => {
  try {
    const ainvoices = await AnInvoice.find().sort({ createdAt: -1 });
    res.status(200).json(ainvoices);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};

// Get a single invoice by ID
export const getAInvoiceById = async (req, res) => {
  try {
    const ainvoices = await AnInvoice.findById(req.params.id);
    if (!ainvoices) {
      return res.status(404).json({ message: "Invoice not found" });
    }
    res.status(200).json(ainvoices);
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};

// Create a new invoice (with multiple items)
export const createAInvoice = async (req, res) => {
  try {
    const newAInvoice = new AnInvoice(req.body); // req.body should include invoiceTo and items[]
    const savedAInvoice = await newAInvoice.save();
    res.status(201).json(savedAInvoice);
  } catch (error) {
    res.status(400).json({ message: "Invalid data", error: error.message });
  }
};

// Update an invoice by ID
export const updateAInvoice = async (req, res) => {
  try {
    const updatedAInvoice = await AnInvoice.findByIdAndUpdate(
      req.params.id,
      req.body, // can update invoiceTo or items[]
      { new: true, runValidators: true }
    );
    if (!updatedAInvoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
    res.status(200).json(updatedAInvoice);
  } catch (error) {
    res.status(400).json({ message: "Invalid data", error: error.message });
  }
};

// Delete an invoice by ID
export const deleteAInvoice = async (req, res) => {
  try {
    const deletedAInvoice = await AnInvoice.findByIdAndDelete(req.params.id);
    if (!deletedAInvoice) {
      return res.status(404).json({ message: "Invoice not found" });
    }
    res.status(200).json({ message: "Invoice deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server Error", error: error.message });
  }
};
