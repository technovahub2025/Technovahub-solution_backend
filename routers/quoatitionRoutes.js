import express from "express";
import {
  getAllQuotations,
  getQuotationById,
  createQuotation,
  updateQuotation,
  deleteQuotation,
} from "../controllers/quotationController.js";

const router = express.Router();

// Routes
router.get("/", getAllQuotations);           // GET all quotations
router.get("/:id", getQuotationById);       // GET single quotation by ID
router.post("/", createQuotation);          // POST create new quotation
router.put("/:id", updateQuotation);        // PUT update quotation by ID
router.delete("/:id", deleteQuotation);     // DELETE quotation by ID

export default router;
