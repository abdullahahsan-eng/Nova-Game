PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  display_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','frozen','closed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  account_number TEXT NOT NULL UNIQUE,
  account_type TEXT NOT NULL DEFAULT 'savings',
  currency TEXT NOT NULL DEFAULT 'NRU',
  balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0),
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','frozen','closed')),
  opened_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS ledger (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL REFERENCES accounts(id),
  transaction_group TEXT NOT NULL,
  type TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK(amount > 0),
  balance_after INTEGER NOT NULL CHECK(balance_after >= 0),
  description TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ledger_account_date ON ledger(account_id, created_at DESC);

CREATE TABLE IF NOT EXISTS loan_applications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  requested_amount INTEGER NOT NULL CHECK(requested_amount > 0),
  tenure_months INTEGER NOT NULL CHECK(tenure_months BETWEEN 1 AND 120),
  purpose TEXT NOT NULL,
  monthly_income INTEGER NOT NULL DEFAULT 0,
  monthly_expenses INTEGER NOT NULL DEFAULT 0,
  existing_emi INTEGER NOT NULL DEFAULT 0,
  eligible_suggestion INTEGER NOT NULL DEFAULT 0,
  sanctioned_amount INTEGER,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','need_documents','verified','approved','rejected','accepted','disbursed','closed')),
  admin_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS card_applications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  requested_limit INTEGER NOT NULL CHECK(requested_limit > 0),
  monthly_income INTEGER NOT NULL DEFAULT 0,
  monthly_expenses INTEGER NOT NULL DEFAULT 0,
  existing_debt INTEGER NOT NULL DEFAULT 0,
  suggested_limit INTEGER NOT NULL DEFAULT 0,
  sanctioned_limit INTEGER,
  status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','need_documents','verified','approved','rejected','accepted','active','blocked','closed')),
  admin_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS virtual_cards (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  masked_number TEXT NOT NULL,
  credit_limit INTEGER NOT NULL DEFAULT 0,
  outstanding INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','blocked','closed')),
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notifications (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id),
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  is_read INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_events (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT REFERENCES users(id),
  action TEXT NOT NULL,
  target_type TEXT NOT NULL,
  target_id TEXT,
  details TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_audit_date ON audit_events(created_at DESC);

CREATE TABLE IF NOT EXISTS offers (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  description TEXT NOT NULL,
  benefit TEXT NOT NULL DEFAULT '',
  cta_label TEXT NOT NULL DEFAULT 'Explore offer',
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  valid_until TEXT NOT NULL DEFAULT '',
  created_by TEXT REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
