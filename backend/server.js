require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
const PORT = Number(process.env.PORT || 5000);
const JWT_SECRET = process.env.JWT_SECRET || 'change-me-in-production';

if (!process.env.DATABASE_URL) {
  console.error('DATABASE_URL is missing in backend/.env');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(cors({
  origin(origin, callback) {
    // Allow browser requests from local development ports and tools.
    if (!origin) return callback(null, true);
    const allowed = [
      process.env.CLIENT_ORIGIN,
      'http://localhost:5500',
      'http://127.0.0.1:5500',
      'http://localhost:5501',
      'http://127.0.0.1:5501',
      'http://localhost:5504',
      'http://127.0.0.1:5504',
      'http://localhost:5505',
      'http://127.0.0.1:5505',
      'http://localhost:5506',
      'http://127.0.0.1:5506',
      'http://localhost:5507',
      'http://127.0.0.1:5507',
      'http://localhost:5508',
      'http://127.0.0.1:5508'
    ].filter(Boolean);
    if (allowed.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  }
}));
app.use(express.json({ limit: '2mb' }));

function safeUser(row) {
  return {
    id: row.id,
    name: row.name,
    email: row.email,
    mobile: row.mobile || '',
    hasPin: !!row.pin_hash,
    biometricEnabled: !!row.biometric_enabled
  };
}

function makeToken(userId) {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: '7d' });
}

function cleanState(raw, walletBalance) {
  const state = raw && typeof raw === 'object' && !Array.isArray(raw) ? { ...raw } : {};
  state.balance = Number(walletBalance || 0);
  // Never persist or return a PIN secret through JSON state.
  state.pin = null;
  if (!Array.isArray(state.transactions)) state.transactions = [];
  if (!Array.isArray(state.coupons)) state.coupons = [];
  if (!Array.isArray(state.notifications)) state.notifications = [];
  if (!state.biometric || typeof state.biometric !== 'object') {
    state.biometric = { enabled: false, credentialId: null };
  }
  if (!state.budget || typeof state.budget !== 'object') state.budget = { categories: {} };
  if (!state.budget.categories || typeof state.budget.categories !== 'object') state.budget.categories = {};
  return state;
}

async function getUserState(userId) {
  const result = await pool.query(`
    SELECT u.*, w.balance
    FROM users u
    LEFT JOIN wallets w ON w.user_id = u.id
    WHERE u.id = $1
  `, [userId]);
  if (!result.rows[0]) return null;
  const row = result.rows[0];
  return { user: safeUser(row), state: cleanState(row.state, row.balance) };
}

async function auth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (_) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }
}

app.get('/api/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (err) {
    res.status(500).json({ ok: false, database: 'disconnected', error: err.message });
  }
});

app.post('/api/auth/register', async (req, res, next) => {
  const { name, email, password, mobile = '' } = req.body || {};
  if (!name || !email || !password || !mobile) {
    return res.status(400).json({ error: 'Name, email, mobile and password are required' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const normalizedEmail = String(email).trim().toLowerCase();
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const existing = await client.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rowCount) {
      await client.query('ROLLBACK');
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const initialState = {
      balance: 0,
      mobile: String(mobile).replace(/\D/g, ''),
      pin: null,
      transactions: [],
      coupons: [],
      notifications: [],
      profile: null,
      biometric: { enabled: false, credentialId: null },
      budget: { categories: {} }
    };

    const userResult = await client.query(`
      INSERT INTO users (name, email, password_hash, mobile, state)
      VALUES ($1, $2, $3, $4, $5::jsonb)
      RETURNING *
    `, [name.trim(), normalizedEmail, passwordHash, String(mobile).replace(/\D/g, ''), JSON.stringify(initialState)]);

    const user = userResult.rows[0];
    await client.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0)', [user.id]);
    await client.query('COMMIT');

    res.status(201).json({
      token: makeToken(user.id),
      user: safeUser(user),
      state: initialState
    });
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    next(err);
  } finally {
    client.release();
  }
});

app.post('/api/auth/login', async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user || !(await bcrypt.compare(String(password || ''), user.password_hash))) {
      return res.status(401).json({ error: 'Incorrect email or password' });
    }
    const data = await getUserState(user.id);
    res.json({ token: makeToken(user.id), ...data });
  } catch (err) { next(err); }
});

app.post('/api/auth/pin-login', async (req, res, next) => {
  try {
    const { email, pin } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user || !user.pin_hash || !(await bcrypt.compare(String(pin || ''), user.pin_hash))) {
      return res.status(401).json({ error: 'Incorrect email or PIN' });
    }
    const data = await getUserState(user.id);
    res.json({ token: makeToken(user.id), ...data });
  } catch (err) { next(err); }
});

app.post('/api/auth/verify-password', auth, async (req, res, next) => {
  try {
    const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.userId]);
    if (!result.rows[0]) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(String(req.body?.password || ''), result.rows[0].password_hash);
    res.json({ valid });
  } catch (err) { next(err); }
});

// Demo-only password reset. In a production app, replace this with an emailed one-time token.
app.post('/api/auth/account-exists', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT 1 FROM users WHERE email = $1', [email]);
    res.json({ exists: result.rowCount > 0 });
  } catch (err) { next(err); }
});

app.post('/api/auth/reset-password', async (req, res, next) => {
  try {
    const email = String(req.body?.email || '').trim().toLowerCase();
    const password = String(req.body?.password || '');
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
    const passwordHash = await bcrypt.hash(password, 12);
    const result = await pool.query('UPDATE users SET password_hash = $1, updated_at = NOW() WHERE email = $2 RETURNING id', [passwordHash, email]);
    if (!result.rowCount) return res.status(404).json({ error: 'Account not found' });
    res.json({ ok: true });
  } catch (err) { next(err); }
});

app.get('/api/me/state', auth, async (req, res, next) => {
  try {
    const data = await getUserState(req.userId);
    if (!data) return res.status(404).json({ error: 'User not found' });
    res.json(data);
  } catch (err) { next(err); }
});

app.put('/api/me/state', auth, async (req, res, next) => {
  const client = await pool.connect();
  try {
    const requestedState = req.body?.state || {};
    const requestedName = String(req.body?.user?.name || '').trim();
    await client.query('BEGIN');

    const existing = await client.query(`
      SELECT u.*, w.balance
      FROM users u LEFT JOIN wallets w ON w.user_id = u.id
      WHERE u.id = $1
      FOR UPDATE OF u
    `, [req.userId]);
    if (!existing.rows[0]) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }

    const oldRow = existing.rows[0];
    const nextState = cleanState(requestedState, requestedState.balance);
    const balance = Number(nextState.balance);
    if (!Number.isFinite(balance) || balance < 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'Invalid wallet balance' });
    }

    // Keep the name/mobile in the users table as well as in the profile/state.
    const nextName = requestedName || oldRow.name;
    await client.query(`
      UPDATE users
      SET name = $1, mobile = COALESCE(NULLIF($2, ''), mobile), state = $3::jsonb, updated_at = NOW()
      WHERE id = $4
    `, [nextName, nextState.mobile || '', JSON.stringify(nextState), req.userId]);

    await client.query(`
      INSERT INTO wallets (user_id, balance, updated_at)
      VALUES ($1, $2, NOW())
      ON CONFLICT (user_id) DO UPDATE SET balance = EXCLUDED.balance, updated_at = NOW()
    `, [req.userId, balance]);

    // Rebuild the normalized transaction mirror from the frontend's transaction list.
    await client.query('DELETE FROM transactions WHERE user_id = $1', [req.userId]);
    for (const tx of nextState.transactions) {
      if (!tx || !tx.id) continue;
      await client.query(`
        INSERT INTO transactions
          (id, user_id, type, name, amount, status, purpose, note, coupon, color, occurred_at)
        VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9, COALESCE($10::timestamptz, NOW()))
      `, [
        req.userId,
        String(tx.type || ''),
        String(tx.name || ''),
        Number(tx.amount || 0),
        String(tx.status || 'success'),
        String(tx.purpose || ''),
        String(tx.note || ''),
        tx.coupon || null,
        tx.color || null,
        tx.isoDate || null
      ]);
    }

    await client.query('COMMIT');
    const data = await getUserState(req.userId);
    res.json(data);
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    next(err);
  } finally { client.release(); }
});

app.put('/api/me/pin', auth, async (req, res, next) => {
  try {
    const pin = String(req.body?.pin || '');
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
    const pinHash = await bcrypt.hash(pin, 12);
    await pool.query('UPDATE users SET pin_hash = $1, updated_at = NOW() WHERE id = $2', [pinHash, req.userId]);
    res.json({ ok: true, hasPin: true });
  } catch (err) { next(err); }
});

app.get('/api/me/transactions', auth, async (req, res, next) => {
  try {
    const result = await pool.query(`
      SELECT id, type, name, amount, status, purpose, note, coupon, color, occurred_at
      FROM transactions WHERE user_id = $1 ORDER BY occurred_at DESC
    `, [req.userId]);
    res.json({ transactions: result.rows });
  } catch (err) { next(err); }
});

app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

pool.query('SELECT 1')
  .then(() => {
    app.listen(PORT, () => console.log(`Nimbus Wallet API running on http://localhost:${PORT}`));
  })
  .catch((err) => {
    console.error('Could not connect to PostgreSQL:', err.message);
    process.exit(1);
  });
