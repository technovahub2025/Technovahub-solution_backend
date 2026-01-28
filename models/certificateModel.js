import mongoose from "mongoose";

const certificateSchema = new mongoose.Schema({
  empID: { type: String, required: true, unique: true },
  empName: { type: String, required: true },
}, { timestamps: true });

const Certificate = mongoose.model("Certificate", certificateSchema);

export default Certificate;