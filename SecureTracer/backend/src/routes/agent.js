import express from "express";
import User from "../models/User.js";
import { appendEvent } from "../utils/audit.js";

const router = express.Router();

function validKey(req) {
  const expected = process.env.AGENT_KEY;
  return expected && req.headers["x-agent-key"] === expected;
}

router.post("/events", async (req, res, next) => {
  try {
    if (!validKey(req)) return res.status(401).json({ message: "Invalid agent key" });
    const { ownerEmail, type, severity, message, metadata = {} } = req.body || {};
    if (!ownerEmail || !type || !severity || !message) return res.status(400).json({ message: "ownerEmail, type, severity and message are required" });
    const owner = await User.findOne({ email: ownerEmail.toLowerCase() });
    if (!owner) return res.status(404).json({ message: "Agent owner account not found" });
    const event = await appendEvent({ owner: owner._id, type, severity, message, metadata: { ...metadata, source: "endpoint-agent", agentName: req.body.agentName || "SecureTracer-Agent" } });
    res.status(201).json({ ok: true, eventId: event._id });
  } catch (e) { next(e); }
});

router.get("/health", async (req, res) => {
  if (!validKey(req)) return res.status(401).json({ message: "Invalid agent key" });
  res.json({ ok: true, service: "SecureTracer Endpoint Agent API" });
});

export default router;
