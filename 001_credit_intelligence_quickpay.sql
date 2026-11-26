-- NovaBank v10 additive migration. Run only after a verified D1 backup.
-- Does not DROP, TRUNCATE, UPDATE, or rewrite existing customer/account/ledger rows.
CREATE TABLE IF NOT EXISTS credit_intelligence_subscriptions (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), plan_code TEXT NOT NULL,
  amount INTEGER NOT NULL CHECK(amount>0), starts_at TEXT NOT NULL, expires_at TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active', payment_account_id TEXT REFERENCES accounts(id),
  payment_reference TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_credit_sub_user_expiry ON credit_intelligence_subscriptions(user_id,status,expires_at);
CREATE TABLE IF NOT EXISTS credit_report_snapshots (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), score INTEGER NOT NULL CHECK(score BETWEEN 300 AND 900),
  report_json TEXT NOT NULL, generated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_credit_snapshot_user ON credit_report_snapshots(user_id,generated_at DESC);
CREATE TABLE IF NOT EXISTS quickpay_beneficiaries (
  id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), beneficiary_account_id TEXT NOT NULL REFERENCES accounts(id),
  beneficiary_account_number TEXT NOT NULL, beneficiary_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'cooling',
  verified_at TEXT NOT NULL DEFAULT (datetime('now')), eligible_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(user_id,beneficiary_account_id)
);
CREATE TABLE IF NOT EXISTS quickpay_transfers (
  id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
  source_account_id TEXT NOT NULL REFERENCES accounts(id), beneficiary_id TEXT NOT NULL REFERENCES quickpay_beneficiaries(id),
  destination_account_id TEXT NOT NULL REFERENCES accounts(id), amount INTEGER NOT NULL, fee INTEGER NOT NULL DEFAULT 0,
  total_debit INTEGER NOT NULL, reference TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
