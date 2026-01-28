import dotenv from "dotenv";
import bcrypt from "bcryptjs";
import Admin from "./models/adminModel.js";
import connectDB from "./config/db.js";

dotenv.config();

const seedAdmin = async () => {
  try {
    await connectDB(); // wait for DB to connect

    const existing = await Admin.findOne({ userName: "admin" });
    if (existing) {
      console.log("Admin already exists");
      process.exit();
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash("admin123", salt);

    const admin = new Admin({
      userName: "admin",
      password: hashedPassword,
    });

    await admin.save();
    console.log("Default admin created successfully");
    process.exit();
  } catch (err) {
    console.error("Seeder error:", err);
    process.exit(1);
  }
};

seedAdmin();
