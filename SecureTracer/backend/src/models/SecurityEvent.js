import mongoose from "mongoose";

const schema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  file: { type: mongoose.Schema.Types.ObjectId, ref: "FileAsset" },
  type: { type: String, required: true },
  severity: { type: String, enum: ["LOW", "MEDIUM", "HIGH", "CRITICAL"], default: "LOW" },
  message: String,
  metadata: mongoose.Schema.Types.Mixed,
  previousHash: String,
  eventHash: { type: String, required: true }
}, { timestamps: true });

export default mongoose.model("SecurityEvent", schema);
