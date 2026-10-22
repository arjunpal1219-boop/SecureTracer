import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import mongoose from "mongoose";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import authRoutes from "./routes/auth.js";
import fileRoutes from "./routes/files.js";
import eventRoutes from "./routes/events.js";
import agentRoutes from "./routes/agent.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000;
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.resolve(__dirname, "..", process.env.UPLOAD_DIR || "uploads");

fs.mkdirSync(uploadDir, { recursive: true });

// Allow Vite's localhost development ports (5173, 5174, 5175, etc.) so
// registration works even when another Vite instance has occupied port 5173.
const allowedOrigins = new Set([
  process.env.CLIENT_URL,
  "http://localhost:5173", "http://localhost:5174", "http://localhost:5175",
  "http://127.0.0.1:5173", "http://127.0.0.1:5174", "http://127.0.0.1:5175"
].filter(Boolean));
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin) || /^http:\/\/(localhost|127\.0\.0\.1):5\d{3}$/.test(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`CORS blocked origin: ${origin}`));
  }
}));
app.use(express.json());
app.use("/uploads", express.static(uploadDir));

app.get("/api/health", (_req, res) => res.json({ ok: true, service: "SecureTracer API" }));

app.use("/api/auth", authRoutes);
app.use("/api/files", fileRoutes);
app.use("/api/events", eventRoutes);
app.use("/api/agent", agentRoutes);

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(err.status || 500).json({ message: err.message || "Server error" });
});

mongoose.connect(process.env.MONGO_URI || "mongodb://127.0.0.1:27017/securetracer")
  .then(() => {
    app.listen(PORT, () => console.log(`SecureTracer API running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err.message);
    process.exit(1);
  });
