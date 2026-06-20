const express = require('express');
const multer  = require('multer');
const cookie  = require('cookie-parser');
const crypto  = require('crypto');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const DATA = path.join(ROOT, 'menu-data.json');

// Password: SHA-256 hash stored in env ADMIN_HASH
// Default password: kumoa2024  (change via env on Railway)
const ADMIN_HASH = process.env.ADMIN_HASH
  || crypto.createHash('sha256').update('kumoa2024').digest('hex');

const sessions = new Map(); // token -> expiry timestamp

app.use(express.json());
app.use(cookie());
app.use(express.static(ROOT));

// ── Multer (foto uploads) ──────────────────────────────
const storage = multer.diskStorage({
  destination: path.join(ROOT, 'assets'),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, `upload-${Date.now()}${ext}`);
  }
});
const upload = multer({ storage, limits: { fileSize: 15 * 1024 * 1024 } });

// ── Auth helpers ───────────────────────────────────────
function requireAuth(req, res, next) {
  const token = req.cookies.admin_token;
  if (!token || !sessions.has(token) || Date.now() > sessions.get(token)) {
    if (token) sessions.delete(token);
    return res.status(401).json({ error: 'No autorizado' });
  }
  next();
}

function readMenu() {
  return JSON.parse(fs.readFileSync(DATA, 'utf8'));
}

function saveMenu(data) {
  fs.writeFileSync(DATA, JSON.stringify(data, null, 2));
}

// ── Auth endpoints ─────────────────────────────────────
app.post('/api/login', (req, res) => {
  const hash = crypto.createHash('sha256').update(req.body.password || '').digest('hex');
  if (hash !== ADMIN_HASH) return res.status(401).json({ error: 'Contraseña incorrecta' });
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, Date.now() + 10 * 60 * 60 * 1000); // 10 h
  res.cookie('admin_token', token, { httpOnly: true, sameSite: 'strict', maxAge: 36000000 });
  res.json({ ok: true });
});

app.post('/api/logout', (req, res) => {
  sessions.delete(req.cookies.admin_token);
  res.clearCookie('admin_token');
  res.json({ ok: true });
});

app.get('/api/auth', (req, res) => {
  const t = req.cookies.admin_token;
  res.json({ autenticado: !!(t && sessions.has(t) && Date.now() < sessions.get(t)) });
});

// ── Menu endpoints ─────────────────────────────────────
app.get('/api/menu', (req, res) => res.json(readMenu()));

app.put('/api/menu/:id', requireAuth, (req, res) => {
  const data = readMenu();
  const i = data.findIndex(p => p.id === req.params.id);
  if (i === -1) return res.status(404).json({ error: 'No encontrado' });
  data[i] = { ...data[i], ...req.body, id: req.params.id };
  saveMenu(data);
  res.json(data[i]);
});

app.post('/api/menu', requireAuth, (req, res) => {
  const data = readMenu();
  const nuevo = { ...req.body, id: `item-${Date.now()}`, disponible: true };
  data.push(nuevo);
  saveMenu(data);
  res.json(nuevo);
});

app.delete('/api/menu/:id', requireAuth, (req, res) => {
  let data = readMenu().filter(p => p.id !== req.params.id);
  saveMenu(data);
  res.json({ ok: true });
});

app.post('/api/upload', requireAuth, upload.single('foto'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Sin archivo' });
  res.json({ foto: `assets/${req.file.filename}` });
});

// ── Pages ──────────────────────────────────────────────
app.get('/', (req, res) => res.sendFile(path.join(ROOT, 'web-kumoa-toledo.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(ROOT, 'admin', 'index.html')));

app.listen(PORT, () => console.log(`✅  Kumoa corriendo en http://localhost:${PORT}`));
