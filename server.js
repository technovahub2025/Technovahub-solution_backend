import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import connectDB from "./config/db.js";
import cookieParser from "cookie-parser";

// Routers
import galleryRoutes from "./routers/galleryRoutes.js";
import courseRoutes from "./routers/courseRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import certificateRoutes from "./routers/certificateRoutes.js";
import softwareRoutes from "./routers/softwareRoutes.js";
import quatation from "./routers/quoatitionRoutes.js"
import invoice from "./routers/invoiceRoutes.js"
import Arinvoice from "./routers/arounInvoiceRoutes.js"
import salaryRoutes from "./routers/salaryRoutes.js";



// Load environment variables based on NODE_ENV
if (process.env.NODE_ENV === "production") {
  dotenv.config({ path: ".env.production" });
} else {
  dotenv.config({ path: ".env.local" });
}

const app = express();

// Render logs this request lifecycle, which makes route and status mismatches visible.
app.use((req, res, next) => {
  const startedAt = Date.now();
  console.log(`[request] ${req.method} ${req.originalUrl}`);

  res.on("finish", () => {
    console.log(
      `[response] ${req.method} ${req.originalUrl} ${res.statusCode} ${Date.now() - startedAt}ms`
    );
  });

  next();
});

// Allowed frontend URLs
const allowedOrigins = [
  "http://localhost:5174",
  "http://localhost:5173",
"https://technovahub-solution.vercel.app",
  
  "https://technova-hub-dynamic-website.vercel.app",
  "https://www.technovahub.in",
  "https://technovahub.in",
  "https://technovahub-solution-is6vunddi-technovas-projects-37226de2.vercel.app",
  "technovahubfrontend-fldvp0knz-technovaservices-projects.vercel.app",
   "https://technovahubfrontend.vercel.app"

];

// CORS setup
app.use(
  cors({
    origin: function (origin, callback) {
      if (!origin || allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error("Not allowed by CORS"));
      }
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);

app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 9000;

// Test route
app.get("/", (req, res) => {
  res.send("API is working 🚀");
});

// Connect to MongoDB
connectDB();

// Routes
app.use("/api/gallery", galleryRoutes);
app.use("/api/courses", courseRoutes);
app.use("/api/auth", authRoutes);
console.log("[startup] Auth routes mounted at /api/auth");
app.use("/api/certificate", certificateRoutes);
app.use("/api/softwareSolution", softwareRoutes);
app.use("/api/quatation", quatation);
app.use("/api/invoice", invoice);
app.use("/api/arouninvoice", Arinvoice);
app.use("/api/salary", salaryRoutes);

// Keep unmatched API requests visible in Render logs.
app.use((req, res, next) => {
  console.warn(`[404] No route matched ${req.method} ${req.originalUrl}`);
  res.status(404).json({ success: false, message: "Route not found" });
});




// Global error handler for CORS
app.use((err, req, res, next) => {
  if (err instanceof Error && err.message === "Not allowed by CORS") {
    res.status(403).json({ message: err.message });
  } else {
    next(err);
  }
});

app.listen(PORT, () => {
  console.log(`[startup] Server running on PORT ${PORT}`);
  console.log(`[startup] NODE_ENV=${process.env.NODE_ENV || "development"}`);
  console.log(`[startup] Google OAuth configuration: ${
    (process.env.GOOGLE_CLIENT_ID || process.env.GOOGLE_DRIVE_CLIENT_ID) &&
    (process.env.GOOGLE_CLIENT_SECRET || process.env.GOOGLE_DRIVE_CLIENT_SECRET) &&
    (process.env.GOOGLE_REDIRECT_URI || process.env.GOOGLE_DRIVE_REDIRECT_URI)
      ? "configured"
      : "missing GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, or GOOGLE_REDIRECT_URI"
  }`);
});
