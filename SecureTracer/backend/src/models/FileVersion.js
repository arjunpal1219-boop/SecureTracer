import mongoose from "mongoose";

const schema = new mongoose.Schema({
  file: { type: mongoose.Schema.Types.ObjectId, ref: "FileAsset", required: true, index: true },
  version: Number,
  sha256: String,
  size: Number,
  storedName: String,
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  note: String
}, { timestamps: true });

export default mongoose.model("FileVersion", schema);
