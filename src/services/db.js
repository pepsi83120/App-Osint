const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DATABASE_PATH || process.env.DB_PATH || path.join(__dirname, '../../data/osint.db');

let db;

function getDb() {
  if (!db) {
    fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
    db = new sqlite3.Database(DB_PATH);
    db.run('PRAGMA journal_mode = WAL');
    initSchema();
  }
  return db;
}

function initSchema() {
  getDb().exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      plan TEXT DEFAULT 'free',
      searches_today INTEGER DEFAULT 0,
      last_search_date TEXT,
      credit_balance INTEGER DEFAULT 30,
      daily_credit_limit INTEGER DEFAULT 0,
      daily_credits_used INTEGER DEFAULT 0,
      last_credit_date TEXT,
      subscription_plan TEXT DEFAULT 'none',
      subscription_expires_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS searches (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      type TEXT NOT NULL,
      query TEXT NOT NULL,
      result TEXT,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS payment_requests (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      offer_id TEXT NOT NULL,
      offer_name TEXT NOT NULL,
      price TEXT NOT NULL,
      proof TEXT,
      status TEXT DEFAULT 'pending',
      created_at TEXT DEFAULT (datetime('now')),
      reviewed_at TEXT,
      reviewed_by TEXT,
      FOREIGN KEY(user_id) REFERENCES users(id)
    );
  `);

  [
    "ALTER TABLE users ADD COLUMN credit_balance INTEGER DEFAULT 30",
    "ALTER TABLE users ADD COLUMN daily_credit_limit INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN daily_credits_used INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN last_credit_date TEXT",
    "ALTER TABLE users ADD COLUMN subscription_plan TEXT DEFAULT 'none'",
    "ALTER TABLE users ADD COLUMN subscription_expires_at TEXT"
  ].forEach((sql) => getDb().run(sql, () => {}));
}

function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    getDb().get(sql, params, (err, row) => {
      if (err) reject(err); else resolve(row);
    });
  });
}

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    getDb().run(sql, params, function(err) {
      if (err) reject(err); else resolve(this);
    });
  });
}

function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    getDb().all(sql, params, (err, rows) => {
      if (err) reject(err); else resolve(rows);
    });
  });
}

module.exports = { getDb, dbGet, dbRun, dbAll };
