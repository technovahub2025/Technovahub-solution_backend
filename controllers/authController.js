// controllers/adminController.js
import Admin from "../models/adminModel.js";
import jwt from "jsonwebtoken";




export const loginAdmin = async (req, res) => {
  try {
    const { userName, password } = req.body;
    const admin = await Admin.findOne({ userName });
    if (!admin) return res.status(401).json({ message: "Invalid username or password" });

    const isMatch = await admin.matchPassword(password);
    if (!isMatch) return res.status(401).json({ message: "Invalid username or password" });

    // Generate JWT token
    const token = jwt.sign({ id: admin._id }, process.env.JWT_SECRET, { expiresIn: "1d" });

    // Set token in cookie
    res.cookie("token", token, {
      httpOnly: true,   // prevents JS access to cookie (security)
      secure: process.env.NODE_ENV === "production", // send only on HTTPS
      maxAge: 24 * 60 * 60 * 1000, // 1 day
      sameSite: "strict",
    });

  res.status(200).json({ 
      success: true, 
      message: "Logged in successfully",
      token,               
      user: { userName }   
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};



export const logoutAdmin = (req, res) => {
  res.cookie("token", "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 0 
  });
  res.status(200).json({ success: true, message: "Logged out successfully" });
};