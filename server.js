const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// Admin password — set via environment variable on Render
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin123';

// Session token store (in-memory — resets on server restart, which is fine for 1 user)
const sessions = new Map();
const SESSION_MAX_AGE = 24 * 60 * 60 * 1000; // 24 hours

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Initialize PostgreSQL connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Create table on startup
(async () => {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS health_submissions (
      id SERIAL PRIMARY KEY,
      submitted_at TIMESTAMP DEFAULT NOW(),
      route_taken TEXT,
      data JSONB,
      viewed BOOLEAN DEFAULT false
    )
  `);
})();

// --- Helper: parse session token from cookie ---
function getSession(req) {
  const cookie = req.headers.cookie || '';
  const match = cookie.match(/session=([a-f0-9]+)/);
  if (!match) return null;
  const token = match[1];
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() - session.created > SESSION_MAX_AGE) {
    sessions.delete(token);
    return null;
  }
  return token;
}

function requireAuth(req, res, next) {
  if (!getSession(req)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

// --- Login endpoint ---
app.post('/admin/api/login', (req, res) => {
  const { password } = req.body;
  if (password !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { created: Date.now() });
  res.cookie('session', token, {
    httpOnly: true,
    secure: true,
    sameSite: 'Strict',
    maxAge: SESSION_MAX_AGE
  });
  res.json({ success: true });
});

// --- Logout endpoint ---
app.post('/admin/api/logout', (req, res) => {
  const token = getSession(req);
  if (token) sessions.delete(token);
  res.clearCookie('session');
  res.json({ success: true });
});

// --- Public: Submit form ---
app.post('/submit', async (req, res) => {
  try {
    const formData = req.body;
    await pool.query(
      'INSERT INTO health_submissions (route_taken, data) VALUES ($1, $2)',
      [formData.routeTaken || '', JSON.stringify(formData)]
    );
    res.json({ success: true, message: 'Form submitted successfully.' });
  } catch (error) {
    console.error('Database error:', error);
    res.status(500).json({ success: false, message: 'Failed to save form. Please try again.' });
  }
});

// --- Protected admin API routes ---
app.get('/admin/api/submissions', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT * FROM health_submissions ORDER BY id DESC');
  res.json(rows);
});

app.get('/admin/api/new-count', requireAuth, async (req, res) => {
  const { rows } = await pool.query('SELECT COUNT(*) as count FROM health_submissions WHERE viewed = false');
  res.json({ count: parseInt(rows[0].count) });
});

app.post('/admin/api/mark-viewed/:id', requireAuth, async (req, res) => {
  await pool.query('UPDATE health_submissions SET viewed = true WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

app.post('/admin/api/mark-all-viewed', requireAuth, async (req, res) => {
  await pool.query('UPDATE health_submissions SET viewed = true');
  res.json({ success: true });
});

app.delete('/admin/api/submissions/:id', requireAuth, async (req, res) => {
  await pool.query('DELETE FROM health_submissions WHERE id = $1', [req.params.id]);
  res.json({ success: true });
});

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
