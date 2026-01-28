import mongoose from "mongoose";

const salarySchema = new mongoose.Schema({
  employeeName: { type: String, required: true },
  employeeId: { type: String, required: true },
  designation: String,
  month: String,
  period: String,
  location: String,
  workType: String,
  bankAccount: String,
  basicSalary: { type: Number, default: 0 },
  housingAllowance: { type: Number, default: 0 },
  transportation: { type: Number, default: 0 },
  performanceBonus: { type: Number, default: 0 },
  totalSalary: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
});

// 🔹 Auto calculate totalSalary before save
salarySchema.pre("save", function (next) {
  this.totalSalary =
    (this.basicSalary || 0) +
    (this.housingAllowance || 0) +
    (this.transportation || 0) +
    (this.performanceBonus || 0);
  next();
});

// 🔹 Auto calculate totalSalary before update
salarySchema.pre("findOneAndUpdate", function (next) {
  const update = this.getUpdate();
  if (update) {
    const {
      basicSalary = 0,
      housingAllowance = 0,
      transportation = 0,
      performanceBonus = 0,
    } = update;
    update.totalSalary =
      (basicSalary || 0) +
      (housingAllowance || 0) +
      (transportation || 0) +
      (performanceBonus || 0);
    this.setUpdate(update);
  }
  next();
});

const SalarySlip = mongoose.model("SalarySlip", salarySchema);
export default SalarySlip;
