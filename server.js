import express from "express";
import fs from "fs";
import dotenv from "dotenv";
import crypto from "crypto-js";
import TelegramBot from "node-telegram-bot-api";

dotenv.config();

const BOT_TOKEN = process.env.BOT_TOKEN;
const SECRET_KEY = process.env.SECRET_KEY || "default_secret";
const PORT = process.env.PORT || 10000;
const FILE_PATH = "./urls.txt";

// --- Bot setup ---
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// --- Express server setup ---
const app = express();
app.use(express.json());

// --- Mã hoá / Giải mã ---
function encrypt(text) {
  return crypto.AES.encrypt(text, SECRET_KEY).toString();
}
function decrypt(ciphertext) {
  try {
    const bytes = crypto.AES.decrypt(ciphertext, SECRET_KEY);
    return bytes.toString(crypto.enc.Utf8);
  } catch {
    return null;
  }
}

// --- Khi người dùng gửi video ---
bot.on("video", async (msg) => {
  const chatId = msg.chat.id;
  const fileId = msg.video.file_id;

  try {
    const file = await bot.getFile(fileId);
    const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;
    const encrypted = encrypt(fileUrl);

    fs.appendFileSync(FILE_PATH, encrypted + "\n");
    await bot.sendMessage(chatId, "✅ Video đã được lưu và mã hoá thành công!");
  } catch (e) {
    console.error(e);
    await bot.sendMessage(chatId, "❌ Gặp lỗi khi xử lý video.");
  }
});

// --- Lệnh /clear ---
bot.onText(/\/clear/, (msg) => {
  fs.writeFileSync(FILE_PATH, "");
  bot.sendMessage(msg.chat.id, "🧹 Đã xoá toàn bộ danh sách video!");
});

// --- Endpoint để PHP đọc video list ---
app.get("/urls.txt", (req, res) => {
  if (!fs.existsSync(FILE_PATH)) return res.send("Không có dữ liệu");

  const encryptedLines = fs.readFileSync(FILE_PATH, "utf8").split("\n").filter(Boolean);
  const decrypted = encryptedLines.map(decrypt).filter(Boolean);

  res.setHeader("Content-Type", "text/plain");
  res.send(decrypted.join("\n"));
});

// --- Check server status ---
app.get("/", (req, res) => {
  res.send("✅ Telegram Bot Server đang hoạt động!");
});

// --- Start Server ---
app.listen(PORT, () => {
  console.log(`✅ Server running on port ${PORT}`);
});
