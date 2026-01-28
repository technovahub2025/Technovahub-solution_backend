import express from "express";
import { createInvoice, deleteInvoice, getAllInvoice, getInvoiceById, updateInvoice } from "../controllers/invoiceController.js";


const router = express.Router();

// Routes
router.get("/", getAllInvoice );           // GET all quotations
router.get("/:id", getInvoiceById);       // GET single quotation by ID
router.post("/", createInvoice);          // POST create new quotation
router.put("/:id", updateInvoice);        // PUT update quotation by ID
router.delete("/:id", deleteInvoice);     // DELETE quotation by ID

export default router;
