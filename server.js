// server.js - Nâng cấp toàn diện bảo mật và tối ưu Stream
import express from "express";
import fs from "fs";
import path from "path";
import dotenv from "dotenv";
import TelegramBot from "node-telegram-bot-api";
import crypto from "crypto";
import axios from "axios";
import { fileURLToPath } from 'url';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// --- CÀI ĐẶT BIẾN MÔI TRƯỜNG ---
const BOT_TOKEN = process.env.BOT_TOKEN;
const SECRET_KEY_HEX = process.env.SECRET_KEY_HEX; 
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;     
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || ""; 
const PORT = parseInt(process.env.PORT || "10000", 10);

if (!BOT_TOKEN || !SECRET_KEY_HEX || !ACCESS_TOKEN) {
  console.error("Missing BOT_TOKEN, SECRET_KEY_HEX or ACCESS_TOKEN in env");
  process.exit(1);
}

// Tạo biến www-origin để kiểm tra bảo mật (ví dụ: https://www.yourdomain.com)
const WWW_ORIGIN = ALLOWED_ORIGIN ? 
    ALLOWED_ORIGIN.replace('https://', 'https://www.').replace('http://', 'http://www.') : '';

// ===================================
// UTILS (Crypto & File I/O)
// ===================================

// utils: AES-256-CBC encrypt/decrypt
function aesEncrypt(plain) {
  const key = Buffer.from(SECRET_KEY_HEX, 'hex');
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plain, 'utf8')), cipher.final()]);
  return iv.toString('hex') + ':' + ct.toString('hex');
}
function aesDecrypt(data) {
  try {
    const key = Buffer.from(SECRET_KEY_HEX, 'hex');
    const [ivHex, ctHex] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const ct = Buffer.from(ctHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return plain.toString('utf8');
  } catch (e) {
    console.error("Lỗi giải mã:", e.message);
    return null;
  }
}

// Hàm so sánh an toàn, chống Timing Attack
function timingSafeCompare(a, b) {
  try {
    // Đảm bảo cả hai buffer có cùng độ dài trước khi so sánh an toàn
    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);
    if (bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA, bufferB);
  } catch (e) {
    return false;
  }
}

const DATA_FILE = path.join(__dirname, 'urls.json');

// read/write helpers
function loadEntries() {
  if (!fs.existsSync(DATA_FILE)) return [];
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    // Xử lý file rỗng
    return raw.trim() ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}
function saveEntries(list) {
  // Thêm try...catch để tránh crash server khi ghi file
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (e) {
    console.error("LỖI NGHIÊM TRỌNG KHI LƯU FILE:", e.message);
  }
}

// add entry
function addEntry(url, type = 'video') {
  const entries = loadEntries();
  const id = crypto.randomBytes(12).toString('hex');
  const enc = aesEncrypt(url);
  const ts = Date.now();
  entries.unshift({ id, enc, type, ts }); 
  if (entries.length > 300) entries.splice(300);
  saveEntries(entries);
  return id;
}

// cleanup older than 3 days
function cleanupOld() {
  const entries = loadEntries();
  const threshold = Date.now() - 3 * 24 * 60 * 60 * 1000;
  const filtered = entries.filter(e => e.ts >= threshold);
  if (filtered.length !== entries.length) saveEntries(filtered);
}

// ===================================
// TELEGRAM BOT (CHẾ ĐỘ PUBLIC)
// ===================================

const bot = new TelegramBot(BOT_TOKEN, { polling: true });

bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Send Video");
});

bot.onText(/\/clear/, (msg) => {
  // Chế độ public: Bất kỳ ai cũng có thể clear
  saveEntries([]);
  bot.sendMessage(msg.chat.id, "✅ Đã xóa toàn bộ.");
});

// handle video or document or text link
bot.on('message', async (msg) => {
  try {
    if (msg.text && msg.text.startsWith('/')) return;

    const chatId = msg.chat.id;

    if (msg.video || msg.document) {
      const fileId = msg.video ? msg.video.file_id : msg.document.file_id;
      const file = await bot.getFile(fileId);
      const fileUrl = `https://api.telegram.org/file/bot${BOT_TOKEN}/${file.file_path}`;
      addEntry(fileUrl, msg.video ? 'video' : 'doc');
      bot.sendMessage(chatId, '✅ Đã lưu media (được mã hoá).');
      return;
    }
    if (msg.text && msg.text.match(/^https?:\/\//i)) {
      addEntry(msg.text.trim(), 'link');
      bot.sendMessage(chatId, '✅ Đã lưu liên kết (được mã hoá).');
      return;
    }
  } catch (e) {
    console.error("Bot msg error:", e);
  }
});

bot.on('polling_error', (error) => {
    console.error(`Lỗi Bot Polling: ${error.code} - ${error.message}`);
});

// ===================================
// EXPRESS APP (BẢO MẬT TRUY CẬP WEB)
// ===================================
const app = express();
app.use(express.json());

// Thêm Middleware Bảo mật và CORS toàn cục
const allowedOriginsList = [ALLOWED_ORIGIN, WWW_ORIGIN, 'http://localhost:3000', 'http://localhost:10000'];
app.use((req, res, next) => {
  // Thêm Security Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // Hạn chế việc tải tài nguyên và nhúng iframe
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; media-src 'self' blob:; object-src 'none'; frame-ancestors 'none';");
  res.setHeader('Vary', 'Origin'); // Cho trình duyệt biết response phụ thuộc vào Origin

  // Xử lý CORS
  const origin = req.get('Origin');
  if (origin && allowedOriginsList.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range');
  }

  // Xử lý Preflight (OPTIONS)
  if (req.method === 'OPTIONS') {
      return res.status(204).end();
  }
  
  next();
});

// Endpoint: server-side PHP fetches this with ?token=ACCESS_TOKEN
app.get('/get-videos', (req, res) => {
  const token = req.query.token || '';
  // Dùng so sánh an toàn, chống Timing Attack
  if (!timingSafeCompare(token, ACCESS_TOKEN)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  cleanupOld();
  const entries = loadEntries();
  const host = req.protocol + '://' + req.get('host');
  
  // Trả về danh sách link stream (ID đã mã hoá, không phải URL gốc)
  const list = entries.map(e => ({
    id: e.id,
    type: e.type,
    ts: e.ts,
    stream: `${host}/stream?id=${e.id}`
  }));
  res.json(list);
});

// Stream proxy: client/browser requests this
app.get('/stream', async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).send('Missing id');

  // Kiểm tra Origin/Referer chính xác
  if (ALLOWED_ORIGIN) {
    const ref = req.get('Referer') || req.get('Origin') || '';
    let requestOrigin = '';
    try {
      // Chuẩn hóa Origin/Referer về dạng Origin (protocol://host)
      requestOrigin = new URL(ref).origin; 
    } catch (e) {} 

    // Chỉ cho phép origin chính, 'www'
    if (requestOrigin !== ALLOWED_ORIGIN && requestOrigin !== WWW_ORIGIN) {
      console.warn(`Blocked stream attempt from: ${ref}`);
      return res.status(403).send('Forbidden - Invalid Origin/Referer');
    }
  }

  const entries = loadEntries();
  const entry = entries.find(e => e.id === id);
  if (!entry) return res.status(404).send('Not found');

  const realUrl = aesDecrypt(entry.enc);
  if (!realUrl) return res.status(500).send('Decrypt failed');

  try {
    const upstream = await axios.get(realUrl, {
      responseType: 'stream',
      headers: {
        'User-Agent': 'Mozilla/5.0',
        // Chuyển tiếp Range header (quan trọng cho tua video)
        'Range': req.headers.range || ''
      },
      maxRedirects: 5,
      timeout: 20000 
    });

    const contentType = upstream.headers['content-type'] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline');

    // Chuyển tiếp các header quan trọng cho client
    const headersToForward = ['accept-ranges', 'content-length', 'content-range', 'last-modified', 'cache-control', 'expires'];
    headersToForward.forEach(h => {
        if (upstream.headers[h]) res.setHeader(h, upstream.headers[h]);
    });

    // Đặt status 206 (Partial Content) nếu có Content-Range
    res.status(upstream.headers['content-range'] ? 206 : 200);

    upstream.data.pipe(res);
  } catch (err) {
    console.error('Stream error:', err && err.message);
    const status = err.response ? err.response.status : 502; 
    if (!res.headersSent) {
      res.status(status).send('Failed to fetch upstream');
    }
  }
});

// Health check
app.get('/health', (req, res) => res.send('ok'));

// Start server
app.listen(PORT, () => {
  console.log(`✅ Server stream đã khởi động trên port ${PORT}`);
  console.log(`✅ Bot Telegram đã kết nối (chế độ public).`);
  console.log(`🌐 ALLOWED_ORIGIN: ${ALLOWED_ORIGIN || 'Tất cả (WARNING)'}`);
});
