import crypto from "crypto";
import SecurityEvent from "../models/SecurityEvent.js";

export async function appendEvent({ owner, file, type, severity, message, metadata = {} }) {
  const previous = await SecurityEvent.findOne({ owner }).sort({ createdAt: -1 });
  const previousHash = previous?.eventHash || "GENESIS";
  const payload = JSON.stringify({
    owner: String(owner), file: file ? String(file) : null, type, severity,
    message, metadata, previousHash, timestamp: new Date().toISOString()
  });
  const eventHash = crypto.createHash("sha256").update(payload).digest("hex");

  return SecurityEvent.create({
    owner, file, type, severity, message, metadata, previousHash, eventHash
  });
}
