import mongoose from "mongoose";

const schema = new mongoose.Schema({
  owner: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true, index: true },
  originalName: { type: String, required: true },
  storedName: { type: String, required: true },
  mimeType: String,
  size: Number,
  sha256: { type: String, required: true },
  status: { type: String, enum: ["VERIFIED", "TAMPERED"], default: "VERIFIED" },
  version: { type: Number, default: 1 }
}, { timestamps: true });

export default mongoose.model("FileAsset", schema);
