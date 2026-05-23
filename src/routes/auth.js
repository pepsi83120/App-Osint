const express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const { dbGet, dbRun } = require('../services/db');
const { requireGuest } = require('../middleware/auth');

const router = express.Router();

router.post('/register', requireGuest, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email et mot de passe requis.' });
  if (password.length < 8) return res.status(400).json({ error: 'Mot de passe trop court (8 car. min).' });
  try {
    const existing = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
    if (existing) return res.status(409).json({ error: 'Email déjà utilisé.' });
    const hash = await bcrypt.hash(password, 12);
    const id = uuidv4();
    await dbRun(
      'INSERT INTO users (id, email, password_hash, credit_balance) VALUES (?, ?, ?, ?)',
      [id, email, hash, 30]
    );
    req.session.userId = id;
    req.session.email = email;
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

router.post('/login', requireGuest, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Champs requis.' });
  try {
    const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);
    if (!user) return res.status(401).json({ error: 'Identifiants incorrects.' });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Identifiants incorrects.' });
    req.session.userId = user.id;
    req.session.email = user.email;
    req.session.plan = user.plan;
    res.json({ success: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Erreur serveur.' });
  }
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ success: true }));
});

router.get('/me', async (req, res) => {
  if (!req.session?.userId) return res.json({ authenticated: false });
  try {
    const user = await dbGet(
      `SELECT id, email, plan, searches_today, credit_balance, daily_credit_limit,
        daily_credits_used, last_credit_date, subscription_plan, subscription_expires_at, created_at
       FROM users WHERE id = ?`,
      [req.session.userId]
    );
    res.json({ authenticated: true, user });
  } catch {
    res.json({ authenticated: false });
  }
});

module.exports = router;
