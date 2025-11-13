import express from "express";
import fs from "fs";
import crypto from "crypto";
import dotenv from "dotenv";

dotenv.config();
const app = express();
app.use(express.json());

const PORT = process.env.PORT || 10000;
const SECRET_KEY = process.env.SECRET_KEY || "default_secret";
const FILE_PATH = "./urls.txt";

// --- Hàm mã hóa dữ liệu ---
function encrypt(text) {
  const cipher = crypto.createCipher("aes-256-cbc", SECRET_KEY);
  let encrypted = cipher.update(text, "utf8", "hex");
  encrypted += cipher.final("hex");
  return encrypted;
}

// --- Hàm giải mã dữ liệu ---
function decrypt(text) {
  const decipher = crypto.createDecipher("aes-256-cbc", SECRET_KEY);
  let decrypted = decipher.update(text, "hex", "utf8");
  decrypted += decipher.final("utf8");
  return decrypted;
}

// --- Bot gửi dữ liệu đến đây (qua POST) ---
app.post("/update", (req, res) => {
  const { urls } = req.body;
  if (!urls || !Array.isArray(urls)) {
    return res.status(400).json({ error: "Invalid data" });
  }

  const encryptedData = urls.map(u => encrypt(u)).join("\n");
  fs.writeFileSync(FILE_PATH, encryptedData, "utf8");
  res.json({ status: "ok", saved: urls.length });
});

// --- PHP sẽ đọc file này ---
app.get("/urls.txt", (req, res) => {
  if (!fs.existsSync(FILE_PATH)) return res.send("No data");

  const raw = fs.readFileSync(FILE_PATH, "utf8");
  const lines = raw.split("\n").filter(Boolean);
  const decrypted = lines.map(decrypt);

  res.setHeader("Content-Type", "text/plain");
  res.send(decrypted.join("\n"));
});

// --- Route kiểm tra ---
app.get("/", (req, res) => {
  res.send("✅ Bot Server running successfully!");
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
