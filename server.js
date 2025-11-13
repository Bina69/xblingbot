// server.js
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

const BOT_TOKEN = process.env.BOT_TOKEN;
const SECRET_KEY_HEX = process.env.SECRET_KEY_HEX; // must be 64 hex chars (32 bytes)
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;     // used by PHP server-side to fetch list
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://xbling.gt.tc"; // e.g. https://yourdomain.com
const PORT = parseInt(process.env.PORT||"10000", 10);

if (!BOT_TOKEN || !SECRET_KEY_HEX || !ACCESS_TOKEN) {
  console.error("Missing BOT_TOKEN, SECRET_KEY_HEX or ACCESS_TOKEN in env");
  process.exit(1);
}

// utils: AES-256-CBC encrypt/decrypt using key buffer from hex
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
    return null;
  }
}

const DATA_FILE = path.join(__dirname, 'urls.json'); // store entries array encrypted per-url

// read/write helpers
function loadEntries() {
  if (!fs.existsSync(DATA_FILE)) return [];
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return JSON.parse(raw);
  } catch {
    return [];
  }
}
function saveEntries(list) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf8');
}

// add entry: store { id, enc, type, ts }
function addEntry(url, type='video') {
  const entries = loadEntries();
  const id = crypto.randomBytes(12).toString('hex');
  const enc = aesEncrypt(url);
  const ts = Date.now();
  entries.unshift({ id, enc, type, ts }); // newest first
  // keep limit (avoid huge files)
  if (entries.length > 300) entries.splice(300);
  saveEntries(entries);
  return id;
}

// cleanup older than 3 days (server-side)
function cleanupOld() {
  const entries = loadEntries();
  const threshold = Date.now() - 3*24*60*60*1000;
  const filtered = entries.filter(e => e.ts >= threshold);
  if (filtered.length !== entries.length) saveEntries(filtered);
}

// Telegram bot: polling
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Bot nhận video: gửi video hoặc link. Sử dụng /clear để xoá.");
});

bot.onText(/\/clear/, (msg) => {
  saveEntries([]);
  bot.sendMessage(msg.chat.id, "✅ Đã xóa toàn bộ.");
});

// handle video or document or text link
bot.on('message', async (msg) => {
  try {
    const chatId = msg.chat.id;
    // only accept media or http links
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
    // ignore others
  } catch (e) {
    console.error("Bot msg error:", e);
  }
});

// Express app
const app = express();
app.use(express.json());

// Endpoint: server-side PHP fetches this with ?token=ACCESS_TOKEN
app.get('/get-videos', (req, res) => {
  const token = req.query.token || '';
  if (token !== ACCESS_TOKEN) return res.status(403).json({ error: 'Forbidden' });
  cleanupOld();
  const entries = loadEntries();
  // return minimal info: id, type, ts, streamUrl (no decrypted real url)
  const host = req.protocol + '://' + req.get('host');
  const list = entries.map(e => ({
    id: e.id,
    type: e.type,
    ts: e.ts,
    stream: `${host}/stream?id=${e.id}` // client will request this; server checks referer
  }));
  res.json(list);
});

// Stream proxy: client/browser requests this to play video.
// Security: require Referer matching ALLOWED_ORIGIN (if set) to prevent abuse
app.get('/stream', async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).send('Missing id');
  if (ALLOWED_ORIGIN) {
    const ref = req.get('Referer') || req.get('Origin') || '';
    if (!ref.startsWith(ALLOWED_ORIGIN)) {
      return res.status(403).send('Forbidden'); // block direct hits
    }
  }
  const entries = loadEntries();
  const entry = entries.find(e => e.id === id);
  if (!entry) return res.status(404).send('Not found');

  const realUrl = aesDecrypt(entry.enc);
  if (!realUrl) return res.status(500).send('Decrypt failed');

  try {
    // fetch upstream as stream and pipe with correct headers
    const upstream = await axios.get(realUrl, { responseType: 'stream', headers: { 'User-Agent': 'Mozilla/5.0' }, maxRedirects: 5, timeout: 15000 });
    const contentType = upstream.headers['content-type'] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    // ensure inline (not attachment)
    res.setHeader('Content-Disposition', 'inline');
    // allow range requests for seeking
    if (upstream.headers['accept-ranges']) res.setHeader('Accept-Ranges', upstream.headers['accept-ranges']);
    if (upstream.headers['content-length']) res.setHeader('Content-Length', upstream.headers['content-length']);
    upstream.data.pipe(res);
  } catch (err) {
    console.error('Stream error:', err && err.message);
    return res.status(502).send('Failed to fetch upstream');
  }
});

// Health
app.get('/health', (req,res)=>res.send('ok'));

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
