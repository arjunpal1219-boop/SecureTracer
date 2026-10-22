import crypto from "crypto";
import fs from "fs/promises";

export async function sha256File(filePath) {
  const buffer = await fs.readFile(filePath);
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

export function sha256Text(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}
