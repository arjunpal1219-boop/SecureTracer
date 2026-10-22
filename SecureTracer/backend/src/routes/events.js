import express from "express";
import { requireAuth } from "../middleware/auth.js";
import SecurityEvent from "../models/SecurityEvent.js";

const router = express.Router();

router.get("/", requireAuth, async (req, res, next) => {
  try {
    const events = await SecurityEvent.find({ owner: req.user.id })
      .populate("file", "originalName status")
      .sort({ createdAt: -1 })
      .limit(100);
    res.json(events);
  } catch (e) { next(e); }
});

router.get("/stats", requireAuth, async (req, res, next) => {
  try {
    const [total, critical, tampered] = await Promise.all([
      SecurityEvent.countDocuments({ owner: req.user.id }),
      SecurityEvent.countDocuments({ owner: req.user.id, severity: "CRITICAL" }),
      SecurityEvent.countDocuments({ owner: req.user.id, type: "TAMPER_DETECTED" })
    ]);
    res.json({ total, critical, tampered });
  } catch (e) { next(e); }
});

export default router;
