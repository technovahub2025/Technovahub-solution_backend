import express from "express";
import { createAInvoice, deleteAInvoice, getAInvoiceById, getAllAInvoice, updateAInvoice } from "../controllers/aInvoiceController.js";



const router = express.Router();

// Routes
router.get("/", getAllAInvoice );           // GET all quotations
router.get("/:id", getAInvoiceById);       // GET single quotation by ID
router.post("/", createAInvoice);          // POST create new quotation
router.put("/:id", updateAInvoice);        // PUT update quotation by ID
router.delete("/:id", deleteAInvoice);     // DELETE quotation by ID

export default router;
