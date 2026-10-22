import express from "express";
import multer from "multer";
import path from "path";
import crypto from "crypto";
import fs from "fs";
import { fileURLToPath } from "url";

import { requireAuth } from "../middleware/auth.js";
import FileAsset from "../models/FileAsset.js";
import FileVersion from "../models/FileVersion.js";
import { sha256File } from "../utils/hash.js";
import { appendEvent } from "../utils/audit.js";

const router = express.Router();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const uploadDir = path.resolve(__dirname, "..", "..", process.env.UPLOAD_DIR || "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, uploadDir),
  filename: (_req, file, cb) => cb(null, `${crypto.randomUUID()}${path.extname(file.originalname)}`)
});
const upload = multer({ storage, limits: { fileSize: 25 * 1024 * 1024 } });

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const files = await FileAsset.find({ owner: req.user.id }).sort({ createdAt: -1 });
    res.json(files);
  } catch (e) { next(e); }
});

router.post("/register", requireAuth, upload.single("file"), async (req, res, next) => {
  try {
    if (!req.file) return res.status(400).json({ message: "File is required" });

    const sha256 = await sha256File(req.file.path);
    const asset = await FileAsset.create({
      owner: req.user.id,
      originalName: req.file.originalname,
      storedName: req.file.filename,
      mimeType: req.file.mimetype,
      size: req.file.size,
      sha256
    });

    await FileVersion.create({
      file: asset._id, version: 1, sha256, size: req.file.size,
      storedName: req.file.filename, createdBy: req.user.id, note: "Initial registration"
    });

    await appendEvent({
      owner: req.user.id, file: asset._id, type: "FILE_REGISTERED",
      severity: "LOW", message: `Registered ${req.file.originalname}`,
      metadata: { sha256, size: req.file.size }
    });

    res.status(201).json(asset);
  } catch (e) { next(e); }
});

router.post("/:id/verify", requireAuth, upload.single("file"), async (req, res, next) => {
  try {
    const asset = await FileAsset.findOne({ _id: req.params.id, owner: req.user.id });
    if (!asset) return res.status(404).json({ message: "File not found" });
    if (!req.file) return res.status(400).json({ message: "File is required for verification" });

    const currentHash = await sha256File(req.file.path);
    const match = currentHash === asset.sha256 && req.file.originalname === asset.originalName;

    asset.status = match ? "VERIFIED" : "TAMPERED";
    await asset.save();

    await appendEvent({
      owner: req.user.id, file: asset._id,
      type: match ? "INTEGRITY_VERIFIED" : "TAMPER_DETECTED",
      severity: match ? "LOW" : "CRITICAL",
      message: match ? `Integrity verified for ${asset.originalName}` : `Tampering detected in ${asset.originalName}`,
      metadata: { expectedHash: asset.sha256, currentHash, expectedName: asset.originalName, uploadedName: req.file.originalname }
    });

    res.json({
      match,
      status: asset.status,
      expectedHash: asset.sha256,
      currentHash
    });
  } catch (e) { next(e); }
});

router.delete("/:id", requireAuth, async (req, res, next) => {
  try {
    const asset = await FileAsset.findOne({ _id: req.params.id, owner: req.user.id });
    if (!asset) return res.status(404).json({ message: "File not found" });

    const storedPath = path.join(uploadDir, asset.storedName);
    try {
      if (fs.existsSync(storedPath)) fs.unlinkSync(storedPath);
    } catch {}

    await FileVersion.deleteMany({ file: asset._id });

    await appendEvent({
      owner: req.user.id,
      file: asset._id,
      type: "FILE_UNREGISTERED",
      severity: "LOW",
      message: `Unregistered ${asset.originalName}`,
      metadata: { originalName: asset.originalName, sha256: asset.sha256 }
    });

    await FileAsset.deleteOne({ _id: asset._id });

    res.json({ message: "File unregistered successfully", file: asset.originalName });
  } catch (e) { next(e); }
});

router.get("/:id/versions", requireAuth, async (req, res, next) => {
  try {
    const asset = await FileAsset.findOne({ _id: req.params.id, owner: req.user.id });
    if (!asset) return res.status(404).json({ message: "File not found" });
    res.json(await FileVersion.find({ file: asset._id }).sort({ version: -1 }));
  } catch (e) { next(e); }
});

export default router;
