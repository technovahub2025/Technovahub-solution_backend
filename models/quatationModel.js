import mongoose from "mongoose";

// ----- ITEM SUBSCHEMA -----
const itemSchema = new mongoose.Schema(
  {
    desc: { type: String, required: true, trim: true },
    hsn: { type: String, required: true },
    gst: { type: Number, required: true, default: 0, min: 0, max: 100 },
    qty: { type: Number, required: true, default: 0 },
    rate: { type: Number, required: true, default: 0 },
    unit: { type: String, default: "" },
    discount: { type: Number, default: 0, min: 0, max: 100 },
    amount: { type: Number, default: 0 },      // before GST
    totalAmount: { type: Number, default: 0 }, // after GST
  },
  { _id: false }
);

// ----- MAIN QUOTATION SCHEMA -----
const quotationSchema = new mongoose.Schema(
  {
    voucherNo: { type: String, unique: true }, // auto generate
    date: { type: Date, default: Date.now },   // today's date
    contactName: { type: String, required: true, trim: true },
    mobile: { type: String, required: true },
    address: { type: String, required: true },

    paymentMode: { type: String, default: "" },
    dispatchedThrough: { type: String, default: "" },
    destination: { type: String, default: "" },
    immediateDated: { type: String, default: "" },

    items: [itemSchema], // multiple items

    subTotal: { type: Number, default: 0 },
    grandTotal: { type: Number, default: 0 },
  },
  { timestamps: true }
);

// ----- PRE-VALIDATE HOOK TO CALCULATE TOTALS & VOUCHER NO -----
quotationSchema.pre("validate", async function (next) {
  // Auto-generate voucherNo for new documents
  if (this.isNew && !this.voucherNo) {
    const year = new Date().getFullYear();
    const nextYear = year + 1;
    const prefix = `ASSE/${String(year).slice(2)}-${String(nextYear).slice(2)}/`;

    const lastQuotation = await mongoose
      .model("Quotation")
      .findOne({ voucherNo: new RegExp(`^${prefix}`) })
      .sort({ createdAt: -1 });

    let nextNumber = 8181; // starting number
    if (lastQuotation) {
      const lastNo = parseInt(lastQuotation.voucherNo.split("/").pop());
      nextNumber = lastNo + 1;
    }
    this.voucherNo = `${prefix}${nextNumber}`;
  }

  // Calculate totals for items
  let subTotal = 0;
  this.items.forEach((item) => {
    const base = item.qty * item.rate;
    const discounted = base * (1 - item.discount / 100);
    const totalWithGST = discounted * (1 + item.gst / 100);

    item.amount = discounted;
    item.totalAmount = totalWithGST;

    subTotal += totalWithGST;
  });

  this.subTotal = subTotal;
  this.grandTotal = subTotal; // can add transport, round off, etc.

  next();
});

const Quotation = mongoose.model("Quotation", quotationSchema);
export default Quotation;
