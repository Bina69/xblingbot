// server.js - BOT TRẢ VỀ DIRECT URL
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

// Biến môi trường
const BOT_TOKEN = process.env.BOT_TOKEN;
const SECRET_KEY_HEX = process.env.SECRET_KEY_HEX; 
const ACCESS_TOKEN = process.env.ACCESS_TOKEN;     
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || ""; 
const PORT = parseInt(process.env.PORT || "10000", 10);
const BASE_URL = process.env.BASE_URL || `https://xblingbot.onrender.com`;

if (!BOT_TOKEN || !SECRET_KEY_HEX || !ACCESS_TOKEN) {
  console.error("Missing required environment variables");
  process.exit(1);
}

// ===================================
// UTILS
// ===================================

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

function timingSafeCompare(a, b) {
  try {
    const bufferA = Buffer.from(a);
    const bufferB = Buffer.from(b);
    if (bufferA.length !== bufferB.length) return false;
    return crypto.timingSafeEqual(bufferA, bufferB);
  } catch (e) {
    return false;
  }
}

const DATA_FILE = path.join(__dirname, 'urls.json');

function loadEntries() {
  if (!fs.existsSync(DATA_FILE)) return [];
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    return raw.trim() ? JSON.parse(raw) : [];
  } catch {
    return [];
  }
}

function saveEntries(list) {
  try {
    fs.writeFileSync(DATA_FILE, JSON.stringify(list, null, 2), 'utf8');
  } catch (e) {
    console.error("Save file error:", e.message);
  }
}

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

function cleanupOld() {
  const entries = loadEntries();
  const threshold = Date.now() - 3 * 24 * 60 * 60 * 1000;
  const filtered = entries.filter(e => e.ts >= threshold);
  if (filtered.length !== entries.length) saveEntries(filtered);
}

// ===================================
// TELEGRAM BOT - WEBHOOK
// ===================================

const bot = new TelegramBot(BOT_TOKEN);
const app = express();

app.use(express.json());

// Webhook route
app.post(`/bot${BOT_TOKEN}`, (req, res) => {
  bot.processUpdate(req.body);
  res.sendStatus(200);
});

bot.onText(/\/start/, (msg) => {
  bot.sendMessage(msg.chat.id, "Send Video");
});

bot.onText(/\/clear/, (msg) => {
  saveEntries([]);
  bot.sendMessage(msg.chat.id, "✅ Đã xóa toàn bộ.");
});

bot.on('message', async (msg) => {
  try {
    if (msg.text && msg.text.startsWith('/')) return;

    const chatId = msg.chat.id;

    if (msg.video || msg.document) {
      const fileId = msg.video ? msg.video.file_id : msg.document.file_id;
      const type = msg.video ? 'video' : 'doc';
      
      try {
        const fileUrl = await bot.getFileLink(fileId);
        addEntry(fileUrl, type);
        bot.sendMessage(chatId, `✅ Đã lưu ${type}`);
      } catch (fileError) {
        console.error("Get file link error:", fileError);
        bot.sendMessage(chatId, '❌ Lỗi khi lấy URL');
      }
      return;
    }
    
    if (msg.text && msg.text.match(/^https?:\/\//i)) {
      addEntry(msg.text.trim(), 'link');
      bot.sendMessage(chatId, '✅ Đã lưu liên kết');
      return;
    }
  } catch (e) {
    console.error("Bot message error:", e);
  }
});

// ===================================
// EXPRESS ROUTES - QUAN TRỌNG: TRẢ VỀ DIRECT URL
// ===================================

// CORS
const allowedOriginsList = [ALLOWED_ORIGIN, 'http://localhost:3000', 'http://localhost:10000'];
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  const origin = req.get('Origin');
  if (origin && allowedOriginsList.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Range');
      res.setHeader('Access-Control-Expose-Headers', 'Content-Length, Content-Range');
  }

  if (req.method === 'OPTIONS') {
      return res.status(204).end();
  }
  
  next();
});

// ENDPOINT MỚI: Trả về DIRECT URLs (không qua stream proxy)
app.get('/get-direct-videos', (req, res) => {
  const token = req.query.token || '';
  if (!timingSafeCompare(token, ACCESS_TOKEN)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  cleanupOld();
  const entries = loadEntries();
  
  // QUAN TRỌNG: Trả về direct URLs thay vì stream URLs
  const list = entries.map(e => {
    const directUrl = aesDecrypt(e.enc);
    return {
      id: e.id,
      type: e.type,
      ts: e.ts,
      stream: directUrl // DIRECT URL từ Telegram
    };
  }).filter(e => e.stream !== null); // Lọc bỏ những URL giải mã thất bại
  
  console.log(`📤 Trả về ${list.length} direct URLs`);
  res.json(list);
});

// ENDPOINT CŨ: Vẫn giữ để tương thích (trả về stream URLs)
app.get('/get-videos', (req, res) => {
  const token = req.query.token || '';
  if (!timingSafeCompare(token, ACCESS_TOKEN)) {
    return res.status(403).json({ error: 'Forbidden' });
  }

  cleanupOld();
  const entries = loadEntries();
  const host = req.protocol + '://' + req.get('host');
  
  const list = entries.map(e => ({
    id: e.id,
    type: e.type,
    ts: e.ts,
    stream: `${host}/stream?id=${e.id}`
  }));
  
  res.json(list);
});

// Stream proxy: Vẫn giữ để hỗ trợ các client cũ
app.get('/stream', async (req, res) => {
  const id = req.query.id;
  if (!id) return res.status(400).send('Missing id');

  if (ALLOWED_ORIGIN) {
    const ref = req.get('Referer') || req.get('Origin') || '';
    let requestOrigin = '';
    try {
      requestOrigin = new URL(ref).origin; 
    } catch (e) {} 

    if (requestOrigin !== ALLOWED_ORIGIN) {
      return res.status(403).send('Forbidden');
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
        'Range': req.headers.range || ''
      },
      maxRedirects: 5,
      timeout: 20000 
    });

    const contentType = upstream.headers['content-type'] || 'application/octet-stream';
    res.setHeader('Content-Type', contentType);
    res.setHeader('Content-Disposition', 'inline');

    const headersToForward = ['accept-ranges', 'content-length', 'content-range', 'last-modified', 'cache-control', 'expires'];
    headersToForward.forEach(h => {
        if (upstream.headers[h]) res.setHeader(h, upstream.headers[h]);
    });

    res.status(upstream.headers['content-range'] ? 206 : 200);
    upstream.data.pipe(res);
  } catch (err) {
    console.error('Stream error:', err.message);
    const status = err.response ? err.response.status : 502; 
    if (!res.headersSent) {
      res.status(status).send('Stream failed');
    }
  }
});

// Health check
app.get('/', (req, res) => {
  res.json({ 
    status: 'ok',
    message: 'Bot is running with direct URLs support',
    endpoints: {
      direct_videos: '/get-direct-videos?token=ACCESS_TOKEN',
      stream_videos: '/get-videos?token=ACCESS_TOKEN'
    }
  });
});

// Setup webhook khi khởi động
async function setupWebhook() {
  try {
    const webhookUrl = `${BASE_URL}/bot${BOT_TOKEN}`;
    await bot.setWebHook(webhookUrl);
    console.log(`✅ Webhook set to: ${webhookUrl}`);
  } catch (error) {
    console.error('❌ Failed to set webhook:', error.message);
  }
}

// Start server
app.listen(PORT, async () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`✅ Bot Telegram ready (Webhook mode)`);
  console.log(`🔗 Direct URLs endpoint: /get-direct-videos`);
  console.log(`🔗 Stream URLs endpoint: /get-videos`);
  await setupWebhook();
});
