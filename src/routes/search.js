const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');
const { runOsintAnalysis } = require('../services/osint');
const { dbGet, dbRun, dbAll } = require('../services/db');

const router = express.Router();
const SEARCH_COST = 10;
const ALLOWED_TYPES = ['username', 'domain', 'email', 'phone'];
const BILLING_OFFERS = [
  {
    id: 'credits_100',
    name: 'Pack 100 credits',
    price: '9,90 EUR',
    description: '10 analyses completes, credits sans expiration.',
    credits: 100,
    dailyCredits: 0,
    durationDays: 0,
    featured: false
  },
  {
    id: 'sub_1m_20',
    name: 'Abonnement 1 mois',
    price: '19,90 EUR',
    description: '20 credits par jour pendant 30 jours, soit 2 analyses/jour.',
    credits: 0,
    dailyCredits: 20,
    durationDays: 30,
    featured: true
  },
  {
    id: 'sub_3m_40',
    name: 'Abonnement 3 mois',
    price: '49,90 EUR',
    description: '40 credits par jour pendant 90 jours, soit 4 analyses/jour.',
    credits: 0,
    dailyCredits: 40,
    durationDays: 90,
    featured: false
  }
];

function todayKey() {
  return new Date().toISOString().split('T')[0];
}

function isSubscriptionActive(user) {
  return user.subscription_expires_at && new Date(user.subscription_expires_at) > new Date();
}

async function checkCredits(req, res, next) {
  const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (!user) return res.status(401).json({ error: 'Utilisateur introuvable.' });

  const today = todayKey();
  const dailyUsed = user.last_credit_date === today ? (user.daily_credits_used || 0) : 0;
  const dailyLimit = isSubscriptionActive(user) ? (user.daily_credit_limit || 0) : 0;
  const dailyRemaining = Math.max(0, dailyLimit - dailyUsed);
  const balance = user.credit_balance || 0;

  if (dailyRemaining >= SEARCH_COST) {
    req.billingCharge = { source: 'daily', nextDailyUsed: dailyUsed + SEARCH_COST, nextBalance: balance };
  } else if (balance >= SEARCH_COST) {
    req.billingCharge = { source: 'balance', nextDailyUsed: dailyUsed, nextBalance: balance - SEARCH_COST };
  } else {
    return res.status(402).json({
      error: `Credits insuffisants. Une analyse coute ${SEARCH_COST} credits.`,
      billing: { cost: SEARCH_COST, creditBalance: balance, dailyRemaining, dailyLimit }
    });
  }

  req.userRecord = user;
  req.today = today;
  next();
}

router.get('/billing/offers', requireAuth, async (req, res) => {
  const user = await dbGet(
    'SELECT credit_balance, daily_credit_limit, daily_credits_used, last_credit_date, subscription_plan, subscription_expires_at FROM users WHERE id = ?',
    [req.session.userId]
  );
  const dailyUsed = user.last_credit_date === todayKey() ? (user.daily_credits_used || 0) : 0;
  const dailyLimit = isSubscriptionActive(user) ? (user.daily_credit_limit || 0) : 0;
  res.json({
    costPerSearch: SEARCH_COST,
    offers: BILLING_OFFERS,
    wallet: {
      creditBalance: user.credit_balance || 0,
      dailyLimit,
      dailyUsed,
      dailyRemaining: Math.max(0, dailyLimit - dailyUsed),
      subscriptionPlan: user.subscription_plan || 'none',
      subscriptionExpiresAt: user.subscription_expires_at
    }
  });
});

router.post('/billing/purchase', requireAuth, async (req, res) => {
  const offer = BILLING_OFFERS.find((item) => item.id === req.body.offerId);
  if (!offer) return res.status(400).json({ error: 'Offre invalide.' });

  const user = await dbGet('SELECT * FROM users WHERE id = ?', [req.session.userId]);
  if (!user) return res.status(401).json({ error: 'Utilisateur introuvable.' });

  if (offer.credits) {
    await dbRun(
      'UPDATE users SET credit_balance = COALESCE(credit_balance, 0) + ? WHERE id = ?',
      [offer.credits, req.session.userId]
    );
  } else {
    const expires = new Date();
    expires.setDate(expires.getDate() + offer.durationDays);
    await dbRun(
      `UPDATE users
       SET subscription_plan = ?, subscription_expires_at = ?, daily_credit_limit = ?,
           daily_credits_used = 0, last_credit_date = ?
       WHERE id = ?`,
      [offer.id, expires.toISOString(), offer.dailyCredits, todayKey(), req.session.userId]
    );
  }

  const updated = await dbGet(
    `SELECT credit_balance, daily_credit_limit, daily_credits_used, last_credit_date,
      subscription_plan, subscription_expires_at FROM users WHERE id = ?`,
    [req.session.userId]
  );
  res.json({ success: true, offer, user: updated, simulated: true });
});

router.post('/search', requireAuth, checkCredits, async (req, res) => {
  const { type, query, options } = req.body;
  if (!type || !query) return res.status(400).json({ error: 'type et query requis.' });
  if (!ALLOWED_TYPES.includes(type)) return res.status(400).json({ error: 'Type invalide.' });
  if (String(query).length > 200) return res.status(400).json({ error: 'Requete trop longue.' });

  try {
    const result = await runOsintAnalysis(type, String(query).trim(), Array.isArray(options) ? options : []);
    const searchId = uuidv4();

    await dbRun(
      'INSERT INTO searches (id, user_id, type, query, result) VALUES (?, ?, ?, ?, ?)',
      [searchId, req.session.userId, type, String(query).trim(), JSON.stringify(result)]
    );

    await dbRun(
      `UPDATE users
       SET searches_today = COALESCE(searches_today, 0) + 1,
           last_search_date = ?,
           credit_balance = ?,
           daily_credits_used = ?,
           last_credit_date = ?
       WHERE id = ?`,
      [req.today, req.billingCharge.nextBalance, req.billingCharge.nextDailyUsed, req.today, req.session.userId]
    );

    const updated = await dbGet(
      'SELECT credit_balance, daily_credit_limit, daily_credits_used, last_credit_date, subscription_plan, subscription_expires_at FROM users WHERE id = ?',
      [req.session.userId]
    );
    const dailyUsed = updated.last_credit_date === req.today ? (updated.daily_credits_used || 0) : 0;
    const dailyLimit = isSubscriptionActive(updated) ? (updated.daily_credit_limit || 0) : 0;

    res.json({
      success: true,
      searchId,
      result,
      billing: {
        cost: SEARCH_COST,
        source: req.billingCharge.source,
        creditBalance: updated.credit_balance || 0,
        dailyLimit,
        dailyUsed,
        dailyRemaining: Math.max(0, dailyLimit - dailyUsed),
        subscriptionPlan: updated.subscription_plan || 'none',
        subscriptionExpiresAt: updated.subscription_expires_at
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message || "Erreur lors de l'analyse." });
  }
});

router.get('/history', requireAuth, async (req, res) => {
  const searches = await dbAll(
    'SELECT id, type, query, created_at FROM searches WHERE user_id = ? ORDER BY created_at DESC LIMIT 50',
    [req.session.userId]
  );
  res.json({ searches });
});

router.get('/history/:id', requireAuth, async (req, res) => {
  const search = await dbGet(
    'SELECT * FROM searches WHERE id = ? AND user_id = ?',
    [req.params.id, req.session.userId]
  );
  if (!search) return res.status(404).json({ error: 'Recherche introuvable.' });
  res.json({ search: { ...search, result: JSON.parse(search.result) } });
});

module.exports = router;
