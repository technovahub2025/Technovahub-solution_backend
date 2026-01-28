import mongoose from "mongoose";

// Item sub-schema
const itemSchema = new mongoose.Schema({
  desc: { type: String, required: true, trim: true },


  hsn: { type: String },
  qty: { type: Number, required: true, default: 0 },
  rate: { type: Number, required: true, default: 0 },
  unit: { type: String, default: "" },
  discount: { type: Number, default: 0, min: 0, max: 100 },
  gst: { type: Number, required: true, default: 0, min: 0, max: 100 },
  amount: { type: Number, default: 0 },      // after discount
  totalAmount: { type: Number, default: 0 }, // after GST
});

const invoiceSchema = new mongoose.Schema(
  {
    invoiceId: { type: String, unique: true, trim: true },
    invoiceTo: { type: String, required: true, trim: true },
      address: { type: String, required: true, trim: true },
    date: { 
      type: Date, 
      default: () => {
        const now = new Date();
        return new Date(now.getFullYear(), now.getMonth(), 1); // first day of month
      } 
    },
    dueDate: { 
      type: Date, 
      default: () => {
        const now = new Date();
        return new Date(now.getFullYear(), now.getMonth() + 1, 0); // last day of month
      } 
    },
    batch: { type: String, default: "" },
    items: [itemSchema], // <-- multiple items
  },
  { timestamps: true }
);

// Pre-save hook
invoiceSchema.pre("save", async function (next) {
  const Invoice = mongoose.model("Invoice", invoiceSchema);

  // Auto-generate sequential invoiceId
  if (!this.invoiceId) {
    try {
      const lastInvoice = await Invoice.findOne({}).sort({ createdAt: -1 }).exec();
      let lastNumber = 0;

      if (lastInvoice && lastInvoice.invoiceId) {
        const parts = lastInvoice.invoiceId.split("-");
        lastNumber = parseInt(parts[1], 10);
      }

      const newNumber = (lastNumber + 1).toString().padStart(3, "0");
      this.invoiceId = `INV-${newNumber}`;
    } catch (err) {
      console.error("Error generating invoiceId:", err);
      return next(err);
    }
  }

  // Calculate amounts for each item
  this.items.forEach(item => {
    const baseAmount = item.qty * item.rate;
    const discounted = baseAmount * (1 - item.discount / 100);
    item.amount = discounted;
    item.totalAmount = discounted * (1 + item.gst / 100);
  });

  next();
});

const Invoice = mongoose.model("Invoice", invoiceSchema);
export default Invoice;
