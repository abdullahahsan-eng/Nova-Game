const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }
});
const uid = () => crypto.randomUUID();
const encoder = new TextEncoder();
const b64 = (bytes) => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const hex = (buf) => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, "0")).join("");

async function digest(text) {
  return hex(await crypto.subtle.digest("SHA-256", encoder.encode(text)));
}
async function passwordHash(password, salt) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: encoder.encode(salt), iterations: 100000, hash: "SHA-256" }, key, 256);
  return hex(bits);
}
function corsHeaders(request) {
  const origin = request.headers.get("Origin") || "";
  return { "access-control-allow-origin": origin, "vary": "Origin", "access-control-allow-headers": "content-type,authorization", "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS" };
}
async function body(request) {
  try { return await request.json(); } catch { return {}; }
}
const STAFF_ROLES = new Set(['branch_manager','loan_officer','credit_officer','cashier','auditor']);
async function ensureSecurityTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS branches (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, status TEXT NOT NULL DEFAULT 'active', created_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
  await env.DB.prepare("INSERT OR IGNORE INTO branches(id,name,status) VALUES('NB-HQ','NovaBank Head Office','active')").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS staff_roles (user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, role_name TEXT NOT NULL CHECK(role_name IN ('branch_manager','loan_officer','credit_officer','cashier','auditor')), branch_id TEXT REFERENCES branches(id), is_active INTEGER NOT NULL DEFAULT 1, permissions_json TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now')), created_by TEXT REFERENCES users(id))`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS auth_rate_limits (rate_key TEXT PRIMARY KEY, window_start INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, updated_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
  await ensureColumn(env, 'staff_roles', 'permissions_json', 'TEXT');
  await ensureColumn(env, 'accounts', 'branch_id', "TEXT NOT NULL DEFAULT 'NB-HQ'");
  await ensureColumn(env, 'users', 'must_change_password', 'INTEGER NOT NULL DEFAULT 0');
  await env.DB.prepare("UPDATE accounts SET branch_id='NB-HQ' WHERE branch_id IS NULL OR branch_id='' ").run();
  await env.DB.prepare("UPDATE staff_roles SET branch_id='NB-HQ' WHERE branch_id IS NULL OR branch_id='' " ).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_accounts_branch ON accounts(branch_id)').run();
}
function isSuperAdmin(user) { return !!user && user.role === 'admin'; }
function staffRole(user) { return user?.role || 'customer'; }

const STAFF_PERMISSION_KEYS = ['customer_lookup','cash_operations','loan_collection','card_collection','loan_review','card_review','money_requests','audit_view'];
function permissionKey(method,path){const m=method.toUpperCase();
 if(path==='/api/admin/customers'&&m==='GET'||path==='/api/admin/customer-details'&&m==='GET'||path==='/api/branch/account-lookup'&&m==='GET')return 'customer_lookup';
 if(path==='/api/branch/account-operation'&&m==='POST')return 'cash_operations';
 if(path==='/api/branch/loan-lookup'&&m==='GET'||path==='/api/branch/loan-payment'&&m==='POST')return 'loan_collection';
 if(path==='/api/branch/card-lookup'&&m==='GET'||path==='/api/branch/card-payment'&&m==='POST')return 'card_collection';
 if(/^\/api\/admin\/loans\/[^/]+\/review$/.test(path))return 'loan_review';
 if(/^\/api\/admin\/cards\/[^/]+\/review$/.test(path)||path==='/api/admin/card-control-requests'&&m==='GET')return 'card_review';
 if(path==='/api/admin/money-requests'&&m==='GET'||/^\/api\/admin\/money-requests\/[^/]+\/(review|archive)$/.test(path))return 'money_requests';
 if(path==='/api/admin/audit'&&m==='GET'||path==='/api/transactions'&&m==='GET')return 'audit_view';
 return null;
}

function hasStaffPermission(user, method, path) {
  if (!user || isSuperAdmin(user)) return isSuperAdmin(user);
  const r = staffRole(user), m = method.toUpperCase();
  let custom=[]; try { custom=JSON.parse(user.staff_permissions_json||'[]'); } catch (_) { custom=[]; }
  if (user.staff_permissions_json !== null && user.staff_permissions_json !== undefined) {
    const key = permissionKey(method,path);
    return !!key && custom.includes(key);
  }
  const match = (re, methods) => methods.includes(m) && re.test(path);
  if (r === 'branch_manager') return (
    match(/^\/api\/admin\/customers$/, ['GET']) || match(/^\/api\/admin\/customer-details$/, ['GET']) ||
    match(/^\/api\/admin\/accounts\/[^/]+\/status$/, ['POST']) || match(/^\/api\/admin\/money-requests$/, ['GET']) ||
    match(/^\/api\/admin\/money-requests\/[^/]+\/(review|archive)$/, ['POST']) ||
    match(/^\/api\/account-closure-requests$/, ['GET']) || match(/^\/api\/admin\/account-closure-requests\/[^/]+\/review$/, ['POST']) || match(/^\/api\/branch\/(account-lookup|loan-lookup|card-lookup)$/, ['GET']) || match(/^\/api\/branch\/(account-operation|loan-payment|card-payment)$/, ['POST'])
  );
  if (r === 'loan_officer') return match(/^\/api\/loans$/, ['GET']) || match(/^\/api\/admin\/loans\/[^/]+\/review$/, ['POST']);
  if (r === 'credit_officer') return match(/^\/api\/cards$/, ['GET']) || match(/^\/api\/admin\/cards\/[^/]+\/review$/, ['POST']) || match(/^\/api\/admin\/card-control-requests$/, ['GET']) || match(/^\/api\/admin\/card-control-requests\/[^/]+\/review$/, ['POST']);
  if (r === 'cashier') return match(/^\/api\/admin\/money-requests$/, ['GET']) || match(/^\/api\/admin\/money-requests\/[^/]+\/(review|archive)$/, ['POST']) || match(/^\/api\/branch\/(account-lookup|loan-lookup|card-lookup)$/, ['GET']) || match(/^\/api\/branch\/(account-operation|loan-payment|card-payment)$/, ['POST']);
  if (r === 'auditor') return match(/^\/api\/transactions$/, ['GET']) || match(/^\/api\/admin\/audit$/, ['GET']) || match(/^\/api\/admin\/summary$/, ['GET']);
  return false;
}
async function rateLimit(env, key, maxAttempts=8, windowSeconds=900) {
  const now = Math.floor(Date.now()/1000), start = now - (now % windowSeconds);
  await env.DB.prepare(`INSERT INTO auth_rate_limits(rate_key,window_start,attempts) VALUES(?,?,1) ON CONFLICT(rate_key) DO UPDATE SET attempts=CASE WHEN auth_rate_limits.window_start=excluded.window_start THEN auth_rate_limits.attempts+1 ELSE 1 END,window_start=excluded.window_start,updated_at=datetime('now')`).bind(key,start).run();
  const row = await env.DB.prepare('SELECT attempts,window_start FROM auth_rate_limits WHERE rate_key=?').bind(key).first();
  return { allowed: Number(row?.attempts||0) <= maxAttempts, attempts: Number(row?.attempts||0), retryAfter: Math.max(1, Number(row?.window_start||start)+windowSeconds-now) };
}
async function clearRateLimit(env, key) { await env.DB.prepare('DELETE FROM auth_rate_limits WHERE rate_key=?').bind(key).run(); }
async function auditSecurityFailure(env, action, target, details={}) {
  try { await audit(env, null, action, 'authentication', target || null, details); } catch (_) {}
}
async function auth(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(
    `SELECT u.id,u.username,u.display_name,u.email,COALESCE(sr.role_name,u.role) AS role,u.role AS base_role,u.status,u.must_change_password,s.expires_at,s.created_at AS session_created_at,sr.branch_id AS staff_branch_id,sr.is_active AS staff_active,sr.permissions_json AS staff_permissions_json
     FROM sessions s JOIN users u ON u.id=s.user_id LEFT JOIN staff_roles sr ON sr.user_id=u.id WHERE s.token_hash=?`
  ).bind(tokenHash).first();
  if (!row) return null;
  if (new Date(row.expires_at).getTime() < Date.now() || Date.now()-new Date(row.session_created_at).getTime() > 8*60*60*1000 || row.status !== "active" || (row.base_role === 'admin' && row.role !== 'admin' && Number(row.staff_active)!==1)) {
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(tokenHash).run().catch(()=>{});
    return null;
  }
  return row;
}
function response(data, status, request) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options":"nosniff", "referrer-policy":"no-referrer", "x-frame-options":"DENY", ...corsHeaders(request) } });
}
async function audit(env, actor, action, targetType, targetId, details = {}) {
  await env.DB.prepare("INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)")
    .bind(uid(), actor?.id || null, action, targetType, targetId || null, JSON.stringify(details)).run();
}
async function notify(env, userId, title, message) {
  await env.DB.prepare("INSERT INTO notifications(id,user_id,title,message) VALUES(?,?,?,?)").bind(uid(), userId, title, message).run();
}
async function ensureTreasury(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS treasury_accounts (
    id TEXT PRIMARY KEY, account_number TEXT NOT NULL UNIQUE, name TEXT NOT NULL,
    current_balance INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS treasury_ledger (
    id TEXT PRIMARY KEY, transaction_group TEXT NOT NULL, type TEXT NOT NULL,
    amount INTEGER NOT NULL DEFAULT 0, balance_after INTEGER NOT NULL,
    description TEXT NOT NULL DEFAULT '', source_type TEXT NOT NULL DEFAULT '', source_id TEXT NOT NULL DEFAULT '',
    actor_user_id TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare("INSERT OR IGNORE INTO treasury_accounts(id,account_number,name,current_balance) VALUES('nova-treasury-main','NB-TREASURY-0001','NovaBank Treasury',0)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS treasury_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)`).run();
  await ensureColumn(env, "treasury_ledger", "reference", "TEXT");
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_ledger_reference ON treasury_ledger(reference) WHERE reference IS NOT NULL").run();
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_treasury_single_opening_balance ON treasury_ledger(type) WHERE type='opening_balance'").run();
  const migrated = await env.DB.prepare("SELECT value FROM treasury_meta WHERE key='legacy_ledger_migrated'").first();
  if (!migrated) {
    await env.DB.prepare(`INSERT OR IGNORE INTO treasury_ledger(id,transaction_group,type,amount,balance_after,description,source_type,source_id,actor_user_id,created_at)
      SELECT 'legacy-'||x.id,COALESCE(x.transaction_group,x.id),x.t_type,x.signed_amount,
        SUM(x.signed_amount) OVER (ORDER BY x.created_at,x.id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW),
        x.description,'legacy_ledger',x.id,NULL,x.created_at
      FROM (SELECT l.id,l.transaction_group,l.created_at,l.description,
        CASE l.type WHEN 'deposit' THEN 'customer_deposit' WHEN 'withdrawal' THEN 'customer_withdrawal' WHEN 'loan_disbursement' THEN 'loan_disbursement' WHEN 'loan_repayment' THEN 'loan_repayment' WHEN 'loan_foreclosure_pending' THEN 'loan_foreclosure_pending' WHEN 'loan_foreclosure' THEN 'loan_foreclosure' WHEN 'loan_foreclosure_reversal' THEN 'foreclosure_reversal' WHEN 'card_repayment' THEN 'card_repayment' WHEN 'transfer_in' THEN 'internal_transfer_in' WHEN 'transfer_out' THEN 'internal_transfer_out' ELSE l.type END AS t_type,
        CASE l.type WHEN 'deposit' THEN l.amount WHEN 'withdrawal' THEN -l.amount WHEN 'loan_disbursement' THEN -l.amount WHEN 'loan_repayment' THEN l.amount WHEN 'loan_foreclosure_pending' THEN l.amount WHEN 'loan_foreclosure' THEN l.amount WHEN 'loan_foreclosure_reversal' THEN -l.amount WHEN 'card_repayment' THEN l.amount WHEN 'card_bill_payment' THEN l.amount ELSE 0 END AS signed_amount
        FROM ledger l) x`).run();
    const sum = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM treasury_ledger").first();
    await env.DB.prepare("UPDATE treasury_accounts SET current_balance=?,updated_at=datetime('now') WHERE id='nova-treasury-main'").bind(Number(sum?.n||0)).run();
    await env.DB.prepare("INSERT OR REPLACE INTO treasury_meta(key,value) VALUES('legacy_ledger_migrated',datetime('now'))").run();
  }
}
async function postTreasury(env, actor, type, signedAmount, description, sourceType='', sourceId='', groupId='') {
  await ensureTreasury(env);
  const current = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger").first();
  const amount = Math.round(Number(signedAmount)||0), balance = Number(current?.balance||0), after = balance + amount;
  if (amount < 0 && after < 0) throw new Error('Insufficient Treasury Funds. Disbursement blocked.');
  const group = groupId || uid();
  await env.DB.batch([
    env.DB.prepare("UPDATE treasury_accounts SET current_balance=?,updated_at=datetime('now') WHERE id='nova-treasury-main'").bind(after),
    env.DB.prepare("INSERT INTO treasury_ledger(id,transaction_group,type,amount,balance_after,description,source_type,source_id,actor_user_id) VALUES(?,?,?,?,?,?,?,?,?)").bind(uid(),group,type,amount,after,String(description||'').slice(0,240),sourceType,sourceId,actor?.id||null)
  ]);
}
async function ensureColumn(env, table, column, definition) {
  const cols = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
  if (!(cols.results || []).some(c => c.name === column)) {
    try { await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`).run(); } catch (e) {
      // Concurrent first requests may race; confirm the column exists before failing.
      const again = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
      if (!(again.results || []).some(c => c.name === column)) throw e;
    }
  }
}
async function ensureApplicationTracking(env) {
  await ensureColumn(env, "loan_applications", "application_number", "TEXT");
  await ensureColumn(env, "card_applications", "application_number", "TEXT");
  await ensureColumn(env, "loan_applications", "processing_fee", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "loan_applications", "file_charge", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "loan_applications", "net_disbursement", "INTEGER NOT NULL DEFAULT 0");
  await env.DB.prepare("UPDATE loan_applications SET application_number='NB-LN-'||strftime('%Y%m%d',created_at)||'-'||upper(substr(replace(id,'-',''),1,8)) WHERE application_number IS NULL OR application_number=''").run();
  await env.DB.prepare("UPDATE card_applications SET application_number='NB-CC-'||strftime('%Y%m%d',created_at)||'-'||upper(substr(replace(id,'-',''),1,8)) WHERE application_number IS NULL OR application_number=''").run();
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_loan_application_number ON loan_applications(application_number)").run();
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_card_application_number ON card_applications(application_number)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS loan_emi_schedule (
    id TEXT PRIMARY KEY, loan_id TEXT NOT NULL REFERENCES demo_loans(id), application_id TEXT NOT NULL REFERENCES loan_applications(id),
    installment_no INTEGER NOT NULL, due_date TEXT NOT NULL, amount INTEGER NOT NULL CHECK(amount>0),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','waived')),
    paid_at TEXT, transaction_group TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(loan_id,installment_no)
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_loan_emi_due ON loan_emi_schedule(loan_id,status,due_date)").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS manual_account_operations (
    id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), actor_user_id TEXT NOT NULL REFERENCES users(id),
    operation TEXT NOT NULL CHECK(operation IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount>0),
    reason TEXT NOT NULL, transaction_group TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  // Extra fields are additive and compatible with existing demo loan rows.
  const loanTable = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='demo_loans'").first();
  if (loanTable) {
    await ensureColumn(env, "demo_loans", "processing_fee", "INTEGER NOT NULL DEFAULT 0");
    await ensureColumn(env, "demo_loans", "file_charge", "INTEGER NOT NULL DEFAULT 0");
    await ensureColumn(env, "demo_loans", "net_disbursed", "INTEGER NOT NULL DEFAULT 0");
  }
}
function newApplicationNumber(prefix, id) {
  const day = new Date().toISOString().slice(0,10).replaceAll('-','');
  return `${prefix}-${day}-${String(id).replaceAll('-','').slice(0,8).toUpperCase()}`;
}
function emiDueDate(installmentNo) {
  const now = new Date();
  const d = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth()+installmentNo, 5));
  return d.toISOString().slice(0,10);
}

async function ensureCardTransactions(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS card_transactions (
    id TEXT PRIMARY KEY, card_id TEXT NOT NULL, user_id TEXT NOT NULL, transaction_group TEXT NOT NULL,
    type TEXT NOT NULL, amount INTEGER NOT NULL, description TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_card_transactions_card_date ON card_transactions(card_id,created_at DESC)").run();
}
async function ensureCardColumns(env) {
  await ensureColumn(env, "card_applications", "existing_emi", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "card_applications", "loan_outstanding", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "virtual_cards", "demo_number", "TEXT NOT NULL DEFAULT ''");
  await ensureColumn(env, "virtual_cards", "activation_pending", "INTEGER NOT NULL DEFAULT 0");
  // Repair legacy cards created with the old unsupported 'inactive' state.
  await env.DB.prepare("UPDATE virtual_cards SET status='active',activation_pending=1 WHERE status='inactive'").run();
}
// Repair legacy cards whose stored outstanding is zero even though recorded card
// activity shows an unpaid balance. Never overwrite a non-zero stored balance.
async function reconcileZeroCardOutstanding(env, userId = null) {
  await ensureCardTransactions(env);
  const scope = userId ? " AND c.user_id=?" : "";
  const sql = `UPDATE virtual_cards AS c
    SET outstanding = (
      SELECT MAX(0, COALESCE(SUM(CASE
        WHEN t.type IN ('joining_fee','purchase','funded_transfer','transfer_fee') THEN t.amount
        WHEN t.type IN ('repayment','bill_payment') THEN -t.amount
        ELSE 0 END),0))
      FROM card_transactions t WHERE t.card_id=c.id
    )
    WHERE c.outstanding=0 ${scope}
      AND EXISTS (SELECT 1 FROM card_transactions t WHERE t.card_id=c.id)
      AND (SELECT COALESCE(SUM(CASE
        WHEN t.type IN ('joining_fee','purchase','funded_transfer','transfer_fee') THEN t.amount
        WHEN t.type IN ('repayment','bill_payment') THEN -t.amount
        ELSE 0 END),0) FROM card_transactions t WHERE t.card_id=c.id) > 0`;
  if (userId) await env.DB.prepare(sql).bind(userId).run();
  else await env.DB.prepare(sql).run();
}
async function ensureCardBillPayments(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS card_bill_payments (
    id TEXT PRIMARY KEY,
    idempotency_key TEXT NOT NULL UNIQUE,
    transaction_group TEXT NOT NULL UNIQUE,
    payer_user_id TEXT NOT NULL REFERENCES users(id),
    card_owner_user_id TEXT NOT NULL REFERENCES users(id),
    account_id TEXT NOT NULL REFERENCES accounts(id),
    card_id TEXT NOT NULL REFERENCES virtual_cards(id),
    amount INTEGER NOT NULL CHECK(amount > 0),
    account_balance_before INTEGER NOT NULL,
    card_outstanding_before INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','completed')),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TRIGGER IF NOT EXISTS validate_card_bill_payment_completion
    BEFORE UPDATE OF status ON card_bill_payments
    WHEN NEW.status='completed' AND OLD.status='pending'
    BEGIN
      SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM accounts WHERE id=NEW.account_id AND balance=NEW.account_balance_before-NEW.amount)
        THEN RAISE(ABORT,'Card bill payer account debit is incomplete') END;
      SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM virtual_cards WHERE id=NEW.card_id AND outstanding=NEW.card_outstanding_before-NEW.amount)
        THEN RAISE(ABORT,'Card bill outstanding update is incomplete') END;
      SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM ledger WHERE transaction_group=NEW.transaction_group AND type='card_bill_payment')
        THEN RAISE(ABORT,'Card bill account ledger entry is missing') END;
      SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM card_transactions WHERE transaction_group=NEW.transaction_group AND type='bill_payment')
        THEN RAISE(ABORT,'Card bill transaction history is missing') END;
      SELECT CASE WHEN NOT EXISTS(SELECT 1 FROM treasury_ledger WHERE transaction_group=NEW.transaction_group AND type='card_bill_payment')
        THEN RAISE(ABORT,'Treasury ledger entry is missing') END;
    END`).run();
}
async function ensureBranchOperations(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
    id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
    user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
    principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL, tenure_months INTEGER NOT NULL,
    remaining_months INTEGER NOT NULL, monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
    processing_fee INTEGER NOT NULL DEFAULT 0, file_charge INTEGER NOT NULL DEFAULT 0, net_disbursed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await ensureColumn(env,'demo_loans','loan_number','TEXT');
  await env.DB.prepare("CREATE UNIQUE INDEX IF NOT EXISTS idx_demo_loan_number ON demo_loans(loan_number) WHERE loan_number IS NOT NULL").run();
  await env.DB.prepare("UPDATE demo_loans SET loan_number='NVL-'||strftime('%Y',created_at)||'-'||upper(substr(replace(id,'-',''),1,10)) WHERE loan_number IS NULL OR loan_number='' ").run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS loan_emi_schedule (id TEXT PRIMARY KEY,loan_id TEXT NOT NULL REFERENCES demo_loans(id),application_id TEXT NOT NULL REFERENCES loan_applications(id),installment_no INTEGER NOT NULL,due_date TEXT NOT NULL,amount INTEGER NOT NULL CHECK(amount>0),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid','waived')),paid_at TEXT,transaction_group TEXT,created_at TEXT NOT NULL DEFAULT (datetime('now')),UNIQUE(loan_id,installment_no))`).run();
  await env.DB.prepare("ALTER TABLE loan_emi_schedule ADD COLUMN paid_amount INTEGER NOT NULL DEFAULT 0").run().catch(()=>{});
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS loan_payment_records (
    id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, loan_id TEXT NOT NULL REFERENCES demo_loans(id),
    loan_number TEXT NOT NULL, borrower_user_id TEXT NOT NULL REFERENCES users(id), payer_user_id TEXT REFERENCES users(id),
    payer_account_id TEXT REFERENCES accounts(id), payment_method TEXT NOT NULL CHECK(payment_method IN ('cash','account')),
    amount INTEGER NOT NULL CHECK(amount>0), reference TEXT NOT NULL UNIQUE, actor_user_id TEXT REFERENCES users(id),
    allocations_json TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS branch_cash_operations (
    id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, account_id TEXT NOT NULL REFERENCES accounts(id),
    actor_user_id TEXT NOT NULL REFERENCES users(id), operation TEXT NOT NULL CHECK(operation IN ('deposit','withdrawal')),
    amount INTEGER NOT NULL CHECK(amount>0), reason TEXT NOT NULL, reference TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS branch_card_payment_records (
    id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, card_id TEXT NOT NULL REFERENCES virtual_cards(id),
    card_owner_user_id TEXT NOT NULL REFERENCES users(id), payer_user_id TEXT REFERENCES users(id),
    payer_account_id TEXT REFERENCES accounts(id), payment_method TEXT NOT NULL CHECK(payment_method IN ('cash','account')),
    amount INTEGER NOT NULL CHECK(amount>0), reference TEXT NOT NULL UNIQUE, actor_user_id TEXT REFERENCES users(id),
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
}
async function branchAllowed(user, method, path) {
  if (isSuperAdmin(user)) return true;
  return hasStaffPermission(user, method, path);
}

async function ensurePayrollTables(env) {
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_employees (
    id TEXT PRIMARY KEY, employee_number TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL UNIQUE REFERENCES users(id),
    account_id TEXT NOT NULL REFERENCES accounts(id), designation TEXT NOT NULL, department TEXT NOT NULL DEFAULT '',
    joining_date TEXT NOT NULL, frequency TEXT NOT NULL CHECK(frequency IN ('monthly','weekly')),
    basic_salary INTEGER NOT NULL CHECK(basic_salary>=0), default_bonus INTEGER NOT NULL DEFAULT 0,
    default_deductions INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','inactive')),
    created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_batches (
    id TEXT PRIMARY KEY, batch_number TEXT NOT NULL UNIQUE, frequency TEXT NOT NULL CHECK(frequency IN ('monthly','weekly')),
    period_start TEXT NOT NULL, period_end TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'draft' CHECK(status IN ('draft','approved','paid','rejected')),
    total_amount INTEGER NOT NULL DEFAULT 0, created_by TEXT NOT NULL REFERENCES users(id), approved_by TEXT,
    approved_at TEXT, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_items (
    id TEXT PRIMARY KEY, batch_id TEXT NOT NULL REFERENCES payroll_batches(id), employee_id TEXT NOT NULL REFERENCES payroll_employees(id),
    basic_salary INTEGER NOT NULL, bonus INTEGER NOT NULL DEFAULT 0, deductions INTEGER NOT NULL DEFAULT 0,
    advance_adjustment INTEGER NOT NULL DEFAULT 0, net_salary INTEGER NOT NULL CHECK(net_salary>=0),
    payment_method TEXT NOT NULL CHECK(payment_method IN ('internal','manual')), payment_reference TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','paid')), paid_at TEXT,
    UNIQUE(batch_id,employee_id)
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_advances (
    id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES payroll_employees(id), amount INTEGER NOT NULL CHECK(amount>0),
    outstanding INTEGER NOT NULL CHECK(outstanding>=0), note TEXT NOT NULL DEFAULT '', created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_compensation_history (
    id TEXT PRIMARY KEY, employee_id TEXT NOT NULL REFERENCES payroll_employees(id),
    basic_salary INTEGER NOT NULL, default_bonus INTEGER NOT NULL DEFAULT 0,
    default_deductions INTEGER NOT NULL DEFAULT 0, effective_date TEXT NOT NULL,
    reason TEXT NOT NULL, changed_by TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_payroll_comp_history_employee ON payroll_compensation_history(employee_id,created_at)').run();
  await env.DB.prepare(`INSERT INTO payroll_compensation_history(id,employee_id,basic_salary,default_bonus,default_deductions,effective_date,reason,changed_by) SELECT lower(hex(randomblob(16))),e.id,e.basic_salary,e.default_bonus,e.default_deductions,e.joining_date,'Opening salary structure at compensation-history migration','system' FROM payroll_employees e WHERE NOT EXISTS (SELECT 1 FROM payroll_compensation_history h WHERE h.employee_id=e.id)`).run();
  await ensureColumn(env,'payroll_employees','archived_at','TEXT');
  await ensureColumn(env,'payroll_employees','archived_by','TEXT');
  await ensureColumn(env,'payroll_advances','requested_amount','INTEGER NOT NULL DEFAULT 0');
  await ensureColumn(env,'payroll_advances','installment_amount','INTEGER NOT NULL DEFAULT 0');
  await ensureColumn(env,'payroll_advances','status',"TEXT NOT NULL DEFAULT 'approved'");
  await ensureColumn(env,'payroll_advances','approved_by','TEXT');
  await ensureColumn(env,'payroll_advances','approved_at','TEXT');
  await ensureColumn(env,'payroll_advances','paid_at','TEXT');
  await ensureColumn(env,'payroll_advances','updated_at','TEXT');
  await env.DB.prepare(`UPDATE payroll_advances SET requested_amount=amount WHERE requested_amount=0`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS payroll_payslips (
    id TEXT PRIMARY KEY, payslip_number TEXT NOT NULL UNIQUE, payroll_item_id TEXT NOT NULL UNIQUE REFERENCES payroll_items(id),
    employee_id TEXT NOT NULL REFERENCES payroll_employees(id), user_id TEXT NOT NULL REFERENCES users(id),
    snapshot_json TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_payroll_items_batch ON payroll_items(batch_id)').run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_payroll_payslips_user ON payroll_payslips(user_id,created_at)').run();
}



async function calculateInternalCreditScore(env,userId) {
  const [cards,payments,late]=await Promise.all([
    env.DB.prepare("SELECT COALESCE(SUM(credit_limit),0) AS lim,COALESCE(SUM(outstanding),0) AS due FROM virtual_cards WHERE user_id=? AND status!='closed'").bind(userId).first().catch(()=>({lim:0,due:0})),
    env.DB.prepare("SELECT COUNT(*) AS n FROM loan_payment_records WHERE borrower_user_id=?").bind(userId).first().catch(()=>({n:0})),
    env.DB.prepare("SELECT COUNT(*) AS n FROM loan_emi_schedule s JOIN demo_loans l ON l.id=s.loan_id WHERE l.user_id=? AND s.status='pending' AND date(s.due_date)<date('now')").bind(userId).first().catch(()=>({n:0}))
  ]);
  const utilization=Number(cards?.lim||0)>0?Math.min(100,Number(cards.due||0)/Number(cards.lim)*100):0;
  return {score:Math.max(300,Math.min(900,Math.round(850-Math.min(260,utilization*2.1)-Math.min(180,Number(late?.n||0)*35)+Math.min(35,Number(payments?.n||0)*3)))),utilization:Math.round(utilization)};
}

async function route(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (method === "GET" && path === "/api/health") return response({ ok: true, app: "NovaBank", mode: "fictional-simulator" }, 200, request);
  await ensureSecurityTables(env);

  // TEMPORARY ADMIN PASSWORD RECOVERY
  if (method === "POST" && path === "/api/admin-password-reset") {
    const resetRateKey = await digest(`reset:${request.headers.get('CF-Connecting-IP')||'unknown'}`);
    const resetLimit = await rateLimit(env, resetRateKey, 5, 900);
    if (!resetLimit.allowed) return response({error:'Too many password reset attempts. Try again later.'},429,request);
    const data = await body(request);

    if (!env.ADMIN_RESET_KEY ||
        data.resetKey !== env.ADMIN_RESET_KEY) {
      return response({ error: "Invalid recovery key" }, 403, request);
    }

    const username = String(data.username || "").trim().toLowerCase();
    const newPassword = String(data.newPassword || "");

    if (username !== "novabankadmin" || newPassword.length < 12) {
      return response({
        error: "Use the existing admin username and a password of at least 12 characters."
      }, 400, request);
    }

    const admin = await env.DB.prepare(
      "SELECT id FROM users WHERE lower(username)=? AND role='admin' LIMIT 1"
    ).bind(username).first();

    if (!admin) {
      return response({ error: "Existing admin not found" }, 404, request);
    }

    const salt = uid();
    const hash = await passwordHash(newPassword, salt);

    await env.DB.prepare(
      "UPDATE users SET password_hash=?, password_salt=?, must_change_password=1 WHERE id=? AND role='admin'"
    ).bind(hash, salt, admin.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(admin.id).run();
    await audit(env,{id:admin.id},'admin_password_reset','user',admin.id,{method:'recovery_key'});

    return response({ ok: true, message: "Admin password updated. Sign in again and choose a new password." }, 200, request);
  }

  // Admin bootstrap endpoint removed after initial Super Admin creation.


  // Password recovery requests are reviewed by an authenticated admin. Never disclose stored passwords.
  if (method === "POST" && path === "/api/password-recovery") {
    const recoveryKey=await digest(`recovery:${request.headers.get('CF-Connecting-IP')||'unknown'}`); const recoveryLimit=await rateLimit(env,recoveryKey,5,3600); if(!recoveryLimit.allowed) return response({error:'Too many recovery requests. Try again later.'},429,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS password_recovery_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), lookup_value TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT, reviewed_by TEXT REFERENCES users(id), admin_note TEXT NOT NULL DEFAULT '')`).run();
    const d = await body(request), lookup = String(d.accountNumber || d.username || '').trim();
    if (lookup.length < 3 || lookup.length > 80) return response({error:'Enter your account number or username.'},400,request);
    const customer = await env.DB.prepare(`SELECT u.id,u.username,a.account_number FROM users u LEFT JOIN accounts a ON a.user_id=u.id WHERE u.role!='admin' AND (lower(u.username)=lower(?) OR upper(a.account_number)=upper(?)) LIMIT 1`).bind(lookup,lookup).first();
    // Return a generic response to reduce account enumeration.
    if (customer) {
      const existing = await env.DB.prepare("SELECT id FROM password_recovery_requests WHERE user_id=? AND status='pending' LIMIT 1").bind(customer.id).first();
      if (!existing) { const rid=uid(); await env.DB.prepare("INSERT INTO password_recovery_requests(id,user_id,lookup_value) VALUES(?,?,?)").bind(rid,customer.id,lookup).run(); await audit(env,{id:customer.id},"password_recovery_requested","user",customer.id,{requestId:rid}); }
    }
    return response({ok:true,message:'If the details match a demo account, a recovery request has been sent for admin review.'},202,request);
  }

  if (method === "POST" && path === "/api/register") {
    const d = await body(request);
    const username = String(d.username || "").trim().toLowerCase(), displayName = String(d.displayName || "").trim();
    const email = String(d.email || "").trim().toLowerCase(), password = String(d.password || "");
    if (!/^[a-z0-9_]{3,24}$/.test(username) || displayName.length < 2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length < 10)
      return response({ error: "Enter a 3–24 character username, name, valid email and password of at least 10 characters." }, 400, request);
    const salt = uid(), userId = uid(), accountId = uid();
    try {
      const hash = await passwordHash(password, salt);
      const accountNumber = "NB" + crypto.getRandomValues(new Uint32Array(1))[0].toString().padStart(10, "0").slice(0, 10);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,username,display_name,email,password_hash,password_salt) VALUES(?,?,?,?,?,?)").bind(userId, username, displayName, email, hash, salt),
        env.DB.prepare("INSERT INTO accounts(id,user_id,account_number,balance,account_type) VALUES(?,?,?,0,?)").bind(accountId, userId, accountNumber, ["savings","current"].includes(String(d.accountType||"savings").toLowerCase())?String(d.accountType).toLowerCase():"savings")
      ]);
      await audit(env, { id: userId }, "customer_registered", "user", userId);
      return response({ ok: true, message: "Account created. Please log in." }, 201, request);
 } catch (e) {
  console.error("Registration error:", e);
  return response({ error: "Registration failed. Check Worker logs." }, 500, request);
}
  }

  if (method === "POST" && path === "/api/login") {
    const d = await body(request), login = String(d.login || "").trim().toLowerCase();
    if (!login || login.length > 120 || String(d.password||'').length > 256) return response({error:'Invalid login or password.'},400,request);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const rateKey = await digest(`login:${ip}:${login}`);
    const limited = await rateLimit(env, rateKey, 8, 900);
    const ipLimited = await rateLimit(env, await digest(`login-ip:${ip}`), 30, 900);
    if (!limited.allowed || !ipLimited.allowed) return response({error:'Too many login attempts. Try again in 15 minutes.'},429,request);
    const user = await env.DB.prepare("SELECT u.*,sr.role_name AS assigned_staff_role,sr.is_active AS staff_active,sr.branch_id AS staff_branch_id FROM users u LEFT JOIN staff_roles sr ON sr.user_id=u.id WHERE u.username=? OR u.email=?").bind(login, login).first();
    const effectiveRole = user?.assigned_staff_role || user?.role;
    const isStaffLogin = d.loginMode === 'admin';
    const staffAssignmentValid = !user?.assigned_staff_role || Number(user.staff_active) === 1;
    const roleAllowed = isStaffLogin ? (effectiveRole !== 'customer' && (effectiveRole === 'admin' || STAFF_ROLES.has(effectiveRole))) : effectiveRole === 'customer';
    const valid = !!user && user.status === 'active' && staffAssignmentValid && roleAllowed && (await passwordHash(String(d.password || ""), user.password_salt)) === user.password_hash;
    if (!valid) {
      await auditSecurityFailure(env,'login_failed',user?.id||login.slice(0,80),{loginMode:isStaffLogin?'staff':'customer',ipHash:await digest(ip),reason:'invalid_credentials_or_role'});
      return response({ error: "Invalid login or password." }, 401, request);
    }
    await clearRateLimit(env, rateKey);
    await clearRateLimit(env, await digest(`login-ip:${ip}`));
    const token = b64(crypto.getRandomValues(new Uint8Array(32)));
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 8).toISOString();
    await env.DB.prepare("DELETE FROM sessions WHERE expires_at < datetime('now')").run();
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(token), user.id, expires).run();
    await audit(env, user, "login", "user", user.id, {role:effectiveRole});
    return response({ token, expiresAt:expires, user: { id:user.id, username:user.username, displayName:user.display_name, email:user.email, role:effectiveRole, branchId:user.staff_branch_id||null, mustChangePassword:Number(user.must_change_password||0)===1 } }, 200, request);
  }

  const user = await auth(request, env);

  // Employee self-service: authenticated customer accounts linked to an active payroll employee.
  if (path.startsWith('/api/payroll/')) {
    if (!user || user.role !== 'customer') return response({error:'Sign in with your employee customer account.'},401,request);
    await ensurePayrollTables(env);
    const employee=await env.DB.prepare(`SELECT e.*,u.display_name,a.account_number FROM payroll_employees e JOIN users u ON u.id=e.user_id JOIN accounts a ON a.id=e.account_id WHERE e.user_id=? AND e.status='active' AND e.archived_at IS NULL LIMIT 1`).bind(user.id).first();
    if(!employee) return response({error:'No active NovaBank employee profile is linked to this customer account.'},404,request);
    if(method==='GET' && path==='/api/payroll/me'){
      const advances=await env.DB.prepare(`SELECT id,amount,requested_amount,installment_amount,outstanding,note,status,created_at,approved_at FROM payroll_advances WHERE employee_id=? ORDER BY created_at DESC LIMIT 100`).bind(employee.id).all();
      const payslips=await env.DB.prepare(`SELECT id,payslip_number,snapshot_json,created_at FROM payroll_payslips WHERE employee_id=? ORDER BY created_at DESC LIMIT 100`).bind(employee.id).all();
      return response({employee,advances:advances.results||[],payslips:(payslips.results||[]).map(x=>({...x,snapshot:JSON.parse(x.snapshot_json)}))},200,request);
    }
    if(method==='POST' && path==='/api/payroll/advances'){
      const d=await body(request), amount=Math.round(Number(d.amount||0)*100), installment=Math.round(Number(d.installmentAmount||0)*100), note=String(d.note||'').trim().slice(0,240);
      if(!Number.isSafeInteger(amount)||amount<100||amount>50000000||!Number.isSafeInteger(installment)||installment<100||installment>amount||note.length<3) return response({error:'Enter a valid advance amount, monthly adjustment and reason.'},400,request);
      const pending=await env.DB.prepare("SELECT id FROM payroll_advances WHERE employee_id=? AND status IN ('pending','approved') AND outstanding>0 LIMIT 1").bind(employee.id).first();
      if(pending)return response({error:'An outstanding or pending salary advance already exists. Resolve it before requesting another.'},409,request);
      const id=uid(); await env.DB.prepare(`INSERT INTO payroll_advances(id,employee_id,amount,outstanding,note,created_by,requested_amount,installment_amount,status) VALUES(?,?,?,0,?,?,?,?,'pending')`).bind(id,employee.id,amount,note,user.id,amount,installment).run();
      await audit(env,user,'payroll_advance_requested','payroll_advance',id,{employeeNumber:employee.employee_number,amount,installment});
      return response({ok:true,message:'Salary advance request submitted for Super Admin approval.'},201,request);
    }
    const slipMatch=path.match(/^\/api\/payroll\/payslips\/([^/]+)$/);
    if(slipMatch && method==='GET'){
      const slip=await env.DB.prepare('SELECT payslip_number,snapshot_json,created_at FROM payroll_payslips WHERE id=? AND employee_id=?').bind(slipMatch[1],employee.id).first();
      if(!slip)return response({error:'Payslip not found.'},404,request);
      return response({payslip:{...slip,snapshot:JSON.parse(slip.snapshot_json)}},200,request);
    }
    return response({error:'Employee payroll route not found.'},404,request);
  }

  // Payroll Control Centre: all writes and approvals are Super Admin-only.
  if (path.startsWith('/api/admin/payroll')) {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    await ensurePayrollTables(env);
    if (method==='GET' && path==='/api/admin/payroll') {
      const employees=await env.DB.prepare(`SELECT e.*,u.display_name,u.username,u.email,a.account_number FROM payroll_employees e JOIN users u ON u.id=e.user_id JOIN accounts a ON a.id=e.account_id ORDER BY e.created_at DESC`).all();
      const batches=await env.DB.prepare(`SELECT b.*,COUNT(i.id) AS employee_count FROM payroll_batches b LEFT JOIN payroll_items i ON i.batch_id=b.id GROUP BY b.id ORDER BY b.created_at DESC LIMIT 100`).all();
      const advances=await env.DB.prepare(`SELECT x.*,e.employee_number,u.display_name FROM payroll_advances x JOIN payroll_employees e ON e.id=x.employee_id JOIN users u ON u.id=e.user_id ORDER BY x.created_at DESC LIMIT 100`).all();
      const payslips=await env.DB.prepare(`SELECT p.id,p.payslip_number,p.created_at,e.employee_number,u.display_name FROM payroll_payslips p JOIN payroll_employees e ON e.id=p.employee_id JOIN users u ON u.id=e.user_id ORDER BY p.created_at DESC LIMIT 100`).all();
      const compensation=await env.DB.prepare(`SELECT h.*,e.employee_number,u.display_name FROM payroll_compensation_history h JOIN payroll_employees e ON e.id=h.employee_id JOIN users u ON u.id=e.user_id ORDER BY h.created_at DESC LIMIT 100`).all();
      return response({employees:employees.results||[],batches:batches.results||[],advances:advances.results||[],payslips:payslips.results||[],compensation:compensation.results||[]},200,request);
    }
    if (method==='POST' && path==='/api/admin/payroll/employees') {
      const d=await body(request), userId=String(d.userId||''), accountNumber=String(d.accountNumber||'').trim();
      const account=await env.DB.prepare(`SELECT a.id,a.user_id,a.account_number FROM accounts a WHERE a.account_number=? AND a.status='active'`).bind(accountNumber).first();
      if(!account || account.user_id!==userId) return response({error:'Choose an active savings account belonging to the selected NovaBank customer.'},400,request);
      const basic=Math.round(Number(d.basicSalary||0)*100), bonus=Math.round(Number(d.bonus||0)*100), deductions=Math.round(Number(d.deductions||0)*100);
      if(!Number.isSafeInteger(basic)||basic<0||!String(d.designation||'').trim()||!['monthly','weekly'].includes(d.frequency)) return response({error:'Enter valid employee and salary details.'},400,request);
      const id=uid(), count=await env.DB.prepare('SELECT COUNT(*) AS n FROM payroll_employees').first(), empNo=`NB-EMP-${String(Number(count?.n||0)+1).padStart(4,'0')}`;
      try { await env.DB.prepare(`INSERT INTO payroll_employees(id,employee_number,user_id,account_id,designation,department,joining_date,frequency,basic_salary,default_bonus,default_deductions) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(id,empNo,userId,account.id,String(d.designation).slice(0,80),String(d.department||'').slice(0,80),String(d.joiningDate||new Date().toISOString().slice(0,10)),d.frequency,basic,bonus,deductions).run(); }
      catch(e){return response({error:'Employee already registered or details are invalid.'},409,request)}
      await audit(env,user,'payroll_employee_created','payroll_employee',id,{employeeNumber:empNo,userId,accountNumber});
      return response({ok:true,employeeNumber:empNo,message:`Employee ${empNo} added to payroll directory.`},201,request);
    }
    const compensationMatch=path.match(/^\/api\/admin\/payroll\/employees\/([^/]+)\/compensation$/);
    if(compensationMatch && method==='POST'){
      const target=await env.DB.prepare('SELECT * FROM payroll_employees WHERE id=?').bind(compensationMatch[1]).first();
      if(!target)return response({error:'Employee not found.'},404,request);
      if(target.archived_at || target.status!=='active')return response({error:'Restore this employee before changing compensation.'},409,request);
      const openDraft=await env.DB.prepare("SELECT i.id FROM payroll_items i JOIN payroll_batches b ON b.id=i.batch_id WHERE i.employee_id=? AND b.status='draft' LIMIT 1").bind(target.id).first();
      if(openDraft)return response({error:'Complete or reject this employee draft payroll batch before changing their salary structure.'},409,request);
      const d=await body(request), basic=Math.round(Number(d.basicSalary)*100), bonus=Math.round(Number(d.defaultBonus)*100), deductions=Math.round(Number(d.defaultDeductions)*100);
      const effective=String(d.effectiveDate||'').trim(), reason=String(d.reason||'').trim().slice(0,240);
      if(!Number.isSafeInteger(basic)||basic<0||basic>100000000000||!Number.isSafeInteger(bonus)||bonus<0||bonus>100000000000||!Number.isSafeInteger(deductions)||deductions<0||deductions>100000000000||!/^\d{4}-\d{2}-\d{2}$/.test(effective)||effective>new Date().toISOString().slice(0,10)||reason.length<3)
        return response({error:'Enter valid salary, incentive, deduction, an effective date no later than today, and a reason.'},400,request);
      if(basic+bonus<deductions)return response({error:'Default deductions cannot exceed basic salary plus default incentive.'},400,request);
      const historyId=uid();
      await env.DB.batch([
        env.DB.prepare("UPDATE payroll_employees SET basic_salary=?,default_bonus=?,default_deductions=?,updated_at=datetime('now') WHERE id=?").bind(basic,bonus,deductions,target.id),
        env.DB.prepare('INSERT INTO payroll_compensation_history(id,employee_id,basic_salary,default_bonus,default_deductions,effective_date,reason,changed_by) VALUES(?,?,?,?,?,?,?,?)').bind(historyId,target.id,basic,bonus,deductions,effective,reason,user.id)
      ]);
      await audit(env,user,'payroll_compensation_updated','payroll_employee',target.id,{employeeNumber:target.employee_number,basicSalary:basic,defaultBonus:bonus,defaultDeductions:deductions,effectiveDate:effective,reason});
      return response({ok:true,message:`Salary structure updated for ${target.employee_number}. New values apply to future payroll drafts.`,historyId},200,request);
    }
    const employeeAction=path.match(/^\/api\/admin\/payroll\/employees\/([^/]+)\/(archive|restore)$/);
    if(employeeAction && method==='POST'){
      const target=await env.DB.prepare('SELECT * FROM payroll_employees WHERE id=?').bind(employeeAction[1]).first();
      if(!target)return response({error:'Employee not found.'},404,request);
      if(employeeAction[2]==='archive'){
        const openAdvance=await env.DB.prepare("SELECT id FROM payroll_advances WHERE employee_id=? AND (status='pending' OR (status='approved' AND outstanding>0)) LIMIT 1").bind(target.id).first();
        if(openAdvance)return response({error:'Resolve pending or outstanding salary advances before archiving this employee.'},409,request);
        const openBatch=await env.DB.prepare("SELECT i.id FROM payroll_items i JOIN payroll_batches b ON b.id=i.batch_id WHERE i.employee_id=? AND b.status='draft' LIMIT 1").bind(target.id).first();
        if(openBatch)return response({error:"Reject or complete this employee's draft payroll batch before archiving."},409,request);
        await env.DB.prepare("UPDATE payroll_employees SET status='inactive',archived_at=datetime('now'),archived_by=?,updated_at=datetime('now') WHERE id=?").bind(user.id,target.id).run();
        await audit(env,user,'payroll_employee_archived','payroll_employee',target.id,{employeeNumber:target.employee_number});
        return response({ok:true,message:`${target.employee_number} archived. Payroll and financial history were preserved.`},200,request);
      }
      await env.DB.prepare("UPDATE payroll_employees SET status='active',archived_at=NULL,archived_by=NULL,updated_at=datetime('now') WHERE id=?").bind(target.id).run();
      await audit(env,user,'payroll_employee_restored','payroll_employee',target.id,{employeeNumber:target.employee_number});
      return response({ok:true,message:`${target.employee_number} restored to the active directory.`},200,request);
    }
    const advanceAction=path.match(/^\/api\/admin\/payroll\/advances\/([^/]+)\/(approve|reject)$/);
    if(advanceAction && method==='POST'){
      const adv=await env.DB.prepare(`SELECT x.*,e.user_id,e.account_id,e.employee_number,a.account_number,a.balance,a.status AS account_status FROM payroll_advances x JOIN payroll_employees e ON e.id=x.employee_id JOIN accounts a ON a.id=e.account_id WHERE x.id=?`).bind(advanceAction[1]).first();
      if(!adv||adv.status!=='pending')return response({error:'Pending salary advance request not found.'},404,request);
      const d=await body(request);
      if(advanceAction[2]==='reject'){
        await env.DB.prepare("UPDATE payroll_advances SET status='rejected',approved_by=?,approved_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND status='pending'").bind(user.id,adv.id).run();
        await notify(env,adv.user_id,'Salary advance declined',String(d.note||'Your salary advance request was declined.').slice(0,240));
        await audit(env,user,'payroll_advance_rejected','payroll_advance',adv.id,{employeeNumber:adv.employee_number,note:String(d.note||'').slice(0,240)});
        return response({ok:true,message:'Salary advance request rejected.'},200,request);
      }
      if(adv.account_status!=='active')return response({error:'Employee linked account is not active.'},409,request);
      await ensureTreasury(env);const treasury=await env.DB.prepare('SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger').first();
      if(Number(treasury?.balance||0)<Number(adv.requested_amount||adv.amount))return response({error:'Insufficient Treasury funds. Advance approval was blocked.'},409,request);
      const amount=Number(adv.requested_amount||adv.amount), group=uid();
      await env.DB.batch([
        env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND status='active'").bind(amount,adv.account_id),
        env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),adv.account_id,group,'salary_advance_credit',amount,Number(adv.balance)+amount,`Salary advance ${adv.employee_number}`),
        env.DB.prepare("UPDATE payroll_advances SET amount=?,outstanding=?,status='approved',approved_by=?,approved_at=datetime('now'),paid_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND status='pending'").bind(amount,amount,user.id,adv.id)
      ]);
      await postTreasury(env,user,'payroll_expense',-amount,`Salary advance ${adv.employee_number}`,'payroll_advance',adv.id,group);
      await notify(env,adv.user_id,'Salary advance approved',`Your salary advance of NVR ${(amount/100).toFixed(2)} has been credited to ${adv.account_number}.`);
      await audit(env,user,'payroll_advance_approved','payroll_advance',adv.id,{employeeNumber:adv.employee_number,amount,installment:adv.installment_amount});
      return response({ok:true,message:'Salary advance approved and credited to the linked NovaBank account.'},200,request);
    }
    if (method==='POST' && path==='/api/admin/payroll/batches') {
      const d=await body(request), frequency=String(d.frequency||''), start=String(d.periodStart||''), end=String(d.periodEnd||'');
      if(!['monthly','weekly'].includes(frequency)||!/^\d{4}-\d{2}-\d{2}$/.test(start)||!/^\d{4}-\d{2}-\d{2}$/.test(end)||end<start) return response({error:'Enter a valid payroll frequency and period.'},400,request);
      const rows=await env.DB.prepare("SELECT * FROM payroll_employees WHERE status='active' AND frequency=? ORDER BY employee_number").bind(frequency).all();
      if(!(rows.results||[]).length) return response({error:`No active ${frequency} employees found.`},400,request);
      const id=uid(), batchNo=`NB-PAY-${new Date().getFullYear()}-${id.slice(0,8).toUpperCase()}`;
      const statements=[env.DB.prepare(`INSERT INTO payroll_batches(id,batch_number,frequency,period_start,period_end,total_amount,created_by) VALUES(?,?,?,?,?,?,?)`).bind(id,batchNo,frequency,start,end,0,user.id)];
      let total=0;
      for(const e of rows.results){
        const existingDraft=await env.DB.prepare("SELECT i.id FROM payroll_items i JOIN payroll_batches b ON b.id=i.batch_id WHERE i.employee_id=? AND b.status='draft' LIMIT 1").bind(e.id).first();
        if(existingDraft)return response({error:`${e.employee_number} already has an open draft payroll item. Complete or reject that batch first.`},409,request);
        const adv=await env.DB.prepare("SELECT id,outstanding,installment_amount FROM payroll_advances WHERE employee_id=? AND status='approved' AND outstanding>0 ORDER BY created_at LIMIT 1").bind(e.id).first();
        const adjustment=adv?Math.min(Number(adv.outstanding),Number(adv.installment_amount||adv.outstanding)):0;
        const gross=Number(e.basic_salary)+Number(e.default_bonus)-Number(e.default_deductions), net=gross-adjustment;
        if(net<0)return response({error:`Salary advance adjustment exceeds net earnings for ${e.employee_number}. Reduce the installment amount.`},400,request);
        total+=net;statements.push(env.DB.prepare(`INSERT INTO payroll_items(id,batch_id,employee_id,basic_salary,bonus,deductions,advance_adjustment,net_salary,payment_method) VALUES(?,?,?,?,?,?,?,?, 'internal')`).bind(uid(),id,e.id,e.basic_salary,e.default_bonus,e.default_deductions,adjustment,net));
      }
      statements[0]=env.DB.prepare(`INSERT INTO payroll_batches(id,batch_number,frequency,period_start,period_end,total_amount,created_by) VALUES(?,?,?,?,?,?,?)`).bind(id,batchNo,frequency,start,end,total,user.id);
      await env.DB.batch(statements); await audit(env,user,'payroll_batch_created','payroll_batch',id,{batchNumber:batchNo,total,employees:rows.results.length,frequency});
      return response({ok:true,batchNumber:batchNo,message:`Draft payroll batch created for ${rows.results.length} employees. Review payment methods and references before approval.`},201,request);
    }
    const payslipDetail=path.match(/^\/api\/admin\/payroll\/payslips\/([^/]+)$/);
    if(payslipDetail && method==='GET'){
      const slip=await env.DB.prepare('SELECT * FROM payroll_payslips WHERE id=?').bind(payslipDetail[1]).first();
      if(!slip)return response({error:'Payslip not found.'},404,request);
      return response({payslip:{...slip,snapshot:JSON.parse(slip.snapshot_json)}},200,request);
    }
    const batchDetail=path.match(/^\/api\/admin\/payroll\/batches\/([^/]+)$/);
    if(batchDetail && method==='GET'){
      const batch=await env.DB.prepare('SELECT * FROM payroll_batches WHERE id=?').bind(batchDetail[1]).first();
      if(!batch)return response({error:'Payroll batch not found.'},404,request);
      const items=await env.DB.prepare(`SELECT i.*,e.employee_number,u.display_name,a.account_number FROM payroll_items i JOIN payroll_employees e ON e.id=i.employee_id JOIN users u ON u.id=e.user_id JOIN accounts a ON a.id=e.account_id WHERE i.batch_id=? ORDER BY e.employee_number`).bind(batch.id).all();
      return response({batch,items:items.results||[]},200,request);
    }
    const itemMatch=path.match(/^\/api\/admin\/payroll\/items\/([^/]+)$/);
    if(itemMatch && method==='PATCH'){
      const d=await body(request);
      const item=await env.DB.prepare(`SELECT i.*,b.id AS batch_id,b.status AS batch_status FROM payroll_items i JOIN payroll_batches b ON b.id=i.batch_id WHERE i.id=?`).bind(itemMatch[1]).first();
      if(!item||item.batch_status!=='draft'||item.status!=='pending')return response({error:'Only items in a draft batch can be edited.'},404,request);
      const updates=[], binds=[]; let auditData={};
      if(d.paymentMethod!==undefined){const methodType=String(d.paymentMethod);if(!['internal','manual'].includes(methodType))return response({error:'Choose internal or manual payment.'},400,request);const ref=String(d.reference||'').trim().slice(0,120);if(methodType==='manual'&&!ref)return response({error:'External payment reference is required.'},400,request);updates.push('payment_method=?','payment_reference=?');binds.push(methodType,ref);auditData.paymentMethod=methodType;auditData.reference=ref;}
      if(d.bonus!==undefined||d.deductions!==undefined){
        const bonus=Math.round(Number(d.bonus!==undefined?d.bonus:Number(item.bonus)/100)*100), deductions=Math.round(Number(d.deductions!==undefined?d.deductions:Number(item.deductions)/100)*100);
        if(!Number.isSafeInteger(bonus)||bonus<0||bonus>100000000000||!Number.isSafeInteger(deductions)||deductions<0||deductions>100000000000)return response({error:'Enter valid non-negative incentive and deduction amounts.'},400,request);
        const net=Number(item.basic_salary)+bonus-deductions-Number(item.advance_adjustment||0);if(net<0)return response({error:'Deductions and advance adjustment cannot exceed gross earnings.'},400,request);
        updates.push('bonus=?','deductions=?','net_salary=?');binds.push(bonus,deductions,net);auditData.bonus=bonus;auditData.deductions=deductions;auditData.netSalary=net;
      }
      if(!updates.length)return response({error:'No payroll item changes supplied.'},400,request);
      binds.push(item.id);await env.DB.prepare(`UPDATE payroll_items SET ${updates.join(',')} WHERE id=?`).bind(...binds).run();
      const total=await env.DB.prepare("SELECT COALESCE(SUM(i.net_salary),0) AS total FROM payroll_items i WHERE i.batch_id=? AND i.status='pending'").bind(item.batch_id).first();
      await env.DB.prepare("UPDATE payroll_batches SET total_amount=? WHERE id=? AND status='draft'").bind(Number(total?.total||0),item.batch_id).run();
      await audit(env,user,'payroll_item_updated','payroll_item',item.id,auditData);
      return response({ok:true,message:'Draft payroll item updated.',batchTotal:Number(total?.total||0)},200,request);
    }
    const batchMatch=path.match(/^\/api\/admin\/payroll\/batches\/([^/]+)\/(approve|reject)$/);
    if(batchMatch && method==='POST'){
      const batch=await env.DB.prepare("SELECT * FROM payroll_batches WHERE id=? AND status='draft'").bind(batchMatch[1]).first();
      if(!batch)return response({error:'Draft payroll batch not found.'},404,request);
      const d=await body(request), items=await env.DB.prepare(`SELECT i.*,e.employee_number,e.account_id,e.user_id,e.designation,e.department,u.display_name,a.account_number FROM payroll_items i JOIN payroll_employees e ON e.id=i.employee_id JOIN users u ON u.id=e.user_id JOIN accounts a ON a.id=e.account_id WHERE i.batch_id=? ORDER BY e.employee_number`).bind(batch.id).all();
      if(batchMatch[2]==='reject'){await env.DB.prepare("UPDATE payroll_batches SET status='rejected',approved_by=?,approved_at=datetime('now') WHERE id=? AND status='draft'").bind(user.id,batch.id).run();await audit(env,user,'payroll_batch_rejected','payroll_batch',batch.id,{note:String(d.note||'').slice(0,240)});return response({ok:true,message:'Payroll batch rejected; no payments were made.'},200,request)}
      if(!items.results?.length)return response({error:'Payroll batch has no employees.'},400,request);
      const total=items.results.reduce((n,x)=>n+Number(x.net_salary),0);
      await ensureTreasury(env);const treasury=await env.DB.prepare('SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger').first();
      if(Number(treasury?.balance||0)<total)return response({error:'Insufficient Treasury funds. Payroll approval was blocked.'},409,request);
      const statements=[];const group=uid();
      for(const it of items.results){if(it.payment_method==='manual'&&!String(it.payment_reference||'').trim())return response({error:`Add an external payment reference for ${it.employee_number}.`},400,request);
        if(it.payment_method==='internal'){
          const acc=await env.DB.prepare("SELECT balance FROM accounts WHERE id=? AND status='active'").bind(it.account_id).first();if(!acc)return response({error:`Linked employee account unavailable: ${it.employee_number}.`},409,request);
          statements.push(env.DB.prepare('UPDATE accounts SET balance=balance+? WHERE id=?').bind(it.net_salary,it.account_id));
          statements.push(env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),it.account_id,group,'salary_credit',it.net_salary,Number(acc.balance)+Number(it.net_salary),`NovaBank payroll ${batch.batch_number}`));
        }
        statements.push(env.DB.prepare("UPDATE payroll_items SET status='paid',paid_at=datetime('now') WHERE id=? AND status='pending'").bind(it.id));
        if(Number(it.advance_adjustment||0)>0){
          const adv=await env.DB.prepare("SELECT id,outstanding FROM payroll_advances WHERE employee_id=? AND status='approved' AND outstanding>0 ORDER BY created_at LIMIT 1").bind(it.employee_id).first();
          if(adv){const remaining=Math.max(0,Number(adv.outstanding)-Number(it.advance_adjustment));statements.push(env.DB.prepare("UPDATE payroll_advances SET outstanding=?,status=?,updated_at=datetime('now') WHERE id=?").bind(remaining,remaining===0?'closed':'approved',adv.id));}
        }
        const snap={employeeNumber:it.employee_number,employeeName:it.display_name||'',designation:it.designation||'',department:it.department||'',accountNumber:it.account_number,periodStart:batch.period_start,periodEnd:batch.period_end,batchNumber:batch.batch_number,basicSalary:Number(it.basic_salary),bonus:Number(it.bonus),deductions:Number(it.deductions),advanceAdjustment:Number(it.advance_adjustment||0),grossEarnings:Number(it.basic_salary)+Number(it.bonus),netSalary:Number(it.net_salary),paymentMethod:it.payment_method,paymentReference:it.payment_reference||'',paidAt:new Date().toISOString(),status:'PAID'};
        const slipId=uid(),slipNo=`NB-PS-${new Date().getFullYear()}-${slipId.slice(0,8).toUpperCase()}`;
        statements.push(env.DB.prepare('INSERT OR IGNORE INTO payroll_payslips(id,payslip_number,payroll_item_id,employee_id,user_id,snapshot_json) VALUES(?,?,?,?,?,?)').bind(slipId,slipNo,it.id,it.employee_id,it.user_id,JSON.stringify(snap)));
      }
      statements.push(env.DB.prepare("UPDATE payroll_batches SET status='paid',approved_by=?,approved_at=datetime('now') WHERE id=? AND status='draft'").bind(user.id,batch.id));
      await env.DB.batch(statements);
      await postTreasury(env,user,'payroll_expense',-total,`Payroll batch ${batch.batch_number}`,'payroll_batch',batch.id,group);
      for(const it of items.results){await notify(env,it.user_id,'Salary credited',`Your NovaBank demo payroll for ${batch.period_start} to ${batch.period_end} has been processed. Batch: ${batch.batch_number}.`)}
      await audit(env,user,'payroll_batch_paid','payroll_batch',batch.id,{batchNumber:batch.batch_number,total,employees:items.results.length});
      return response({ok:true,message:`Payroll batch ${batch.batch_number} marked paid.`},200,request);
    }
    return response({error:'Payroll route not found.'},404,request);
  }

  // Staff directory and role assignments are Super Admin-only.
  if (path === '/api/admin/staff' && method === 'GET') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const rows = await env.DB.prepare(`SELECT u.id,u.username,u.display_name,u.email,u.status,sr.role_name,sr.branch_id,sr.is_active,sr.permissions_json,sr.created_at FROM staff_roles sr JOIN users u ON u.id=sr.user_id ORDER BY sr.created_at DESC`).all();
    const branches = await env.DB.prepare("SELECT id,name,status FROM branches ORDER BY name").all();
    return response({staff:rows.results||[],branches:branches.results||[]},200,request);
  }
  if (path === '/api/admin/branches' && method === 'GET') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const rows=await env.DB.prepare("SELECT id,name,status FROM branches ORDER BY name").all();
    return response({branches:rows.results||[]},200,request);
  }
  const accountBranchMatch=path.match(/^\/api\/admin\/accounts\/([^/]+)\/branch$/);
  if (accountBranchMatch && method==='POST') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), branchId=String(d.branchId||'');
    const branch=await env.DB.prepare("SELECT id,name FROM branches WHERE id=? AND status='active'").bind(branchId).first();
    if(!branch) return response({error:'Select an active branch.'},400,request);
    const account=await env.DB.prepare("SELECT id,account_number,branch_id FROM accounts WHERE id=?").bind(accountBranchMatch[1]).first();
    if(!account) return response({error:'Account not found.'},404,request);
    const oldBranch=account.branch_id||'NB-HQ';
    await env.DB.prepare("UPDATE accounts SET branch_id=? WHERE id=?").bind(branchId,account.id).run();
    await audit(env,user,'account_branch_changed','account',account.id,{accountNumber:account.account_number,fromBranch:oldBranch,toBranch:branchId});
    return response({ok:true,message:`Account assigned to ${branch.name}.`},200,request);
  }
  if (path === '/api/admin/branches' && method === 'POST') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), name=String(d.name||'').trim().slice(0,80), id=String(d.id||'').trim().toUpperCase();
    if (!/^[A-Z0-9-]{2,24}$/.test(id) || name.length<2) return response({error:'Enter a branch ID (2–24 letters/numbers/hyphens) and name.'},400,request);
    try { await env.DB.prepare("INSERT INTO branches(id,name,status) VALUES(?,?,'active')").bind(id,name).run(); await audit(env,user,'branch_created','branch',id,{name}); return response({ok:true},201,request); }
    catch (_) { return response({error:'Branch ID or name already exists.'},409,request); }
  }
  if (path === '/api/admin/staff' && method === 'POST') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), username=String(d.username||'').trim().toLowerCase(), displayName=String(d.displayName||'').trim(), email=String(d.email||'').trim().toLowerCase(), password=String(d.password||''), role=String(d.role||''), branchId=String(d.branchId||'NB-HQ');
    if (!/^[a-z0-9_]{3,24}$/.test(username) || displayName.length<2 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || password.length<12 || password.length>128 || !STAFF_ROLES.has(role)) return response({error:'Enter valid staff details, a permitted role, and a password of 12–128 characters.'},400,request);
    const branch=await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first();
    if (!branch) return response({error:'Select an active branch.'},400,request);
    const id=uid(), salt=uid(), hash=await passwordHash(password,salt);
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO users(id,username,display_name,email,password_hash,password_salt,role,status) VALUES(?,?,?,?,?,?,'admin','active')").bind(id,username,displayName,email,hash,salt),
        env.DB.prepare("INSERT INTO staff_roles(user_id,role_name,branch_id,is_active,permissions_json,created_by) VALUES(?,?,?,1,?,?)").bind(id,role,branchId,JSON.stringify(Array.isArray(d.permissions)?d.permissions.filter(x=>STAFF_PERMISSION_KEYS.includes(x)):[]),user.id)
      ]);
      await audit(env,user,'staff_created','staff_user',id,{username,role,branchId});
      return response({ok:true,message:'Staff account created. Share the initial password securely.'},201,request);
    } catch (_) { return response({error:'Username or email already exists; no staff account was created.'},409,request); }
  }
  const staffResetMatch=path.match(/^\/api\/admin\/staff\/([^/]+)\/reset-password$/);
  if (staffResetMatch && method==='POST') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), password=String(d.temporaryPassword||'');
    if(password.length<12||password.length>128) return response({error:'Temporary password must be 12–128 characters.'},400,request);
    const staff=await env.DB.prepare("SELECT u.id,u.username FROM users u JOIN staff_roles sr ON sr.user_id=u.id WHERE u.id=?").bind(staffResetMatch[1]).first();
    if(!staff) return response({error:'Staff account not found.'},404,request);
    const salt=uid(),hash=await passwordHash(password,salt);
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,must_change_password=1 WHERE id=?").bind(hash,salt,staff.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(staff.id).run();
    await audit(env,user,'staff_password_reset','staff_user',staff.id,{username:staff.username,mustChangePassword:true});
    return response({ok:true,message:'Temporary password set. All existing staff sessions were revoked; the user must change it at next login.'},200,request);
  }
  const staffMatch=path.match(/^\/api\/admin\/staff\/([^/]+)$/);
  if (staffMatch && method==='PATCH') {
    if (!isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), target=await env.DB.prepare("SELECT sr.*,u.username FROM staff_roles sr JOIN users u ON u.id=sr.user_id WHERE sr.user_id=?").bind(staffMatch[1]).first();
    if (!target) return response({error:'Staff account not found.'},404,request);
    const role=String(d.role||target.role_name), active=d.active===undefined?Number(target.is_active): (d.active?1:0), branchId=String(d.branchId||target.branch_id||'NB-HQ');
    if (!STAFF_ROLES.has(role)) return response({error:'Invalid staff role.'},400,request);
    const branch=await env.DB.prepare("SELECT id FROM branches WHERE id=? AND status='active'").bind(branchId).first();
    if (role==='branch_manager'&&!branch) return response({error:'Select an active branch.'},400,request);
    const permissions=Array.isArray(d.permissions)?JSON.stringify(d.permissions.filter(x=>STAFF_PERMISSION_KEYS.includes(x))):target.permissions_json||'[]';
    await env.DB.prepare("UPDATE staff_roles SET role_name=?,branch_id=?,is_active=?,permissions_json=?,updated_at=datetime('now') WHERE user_id=?").bind(role,branchId,active,permissions,staffMatch[1]).run();
    if (!active) await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(staffMatch[1]).run();
    await audit(env,user,active?'staff_role_updated':'staff_access_revoked','staff_user',staffMatch[1],{role,active,branchId});
    return response({ok:true,message:active?'Staff permissions updated.':'Staff access disabled and sessions revoked.'},200,request);
  }

  if (path.startsWith('/api/admin/password-recovery')) {
    if (!hasStaffPermission(user, method, path)) return response({error:'Insufficient role permission.'},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS password_recovery_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), lookup_value TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT, reviewed_by TEXT REFERENCES users(id), admin_note TEXT NOT NULL DEFAULT '')`).run();
    if (method === 'GET' && path === '/api/admin/password-recovery') {
      const rows=await env.DB.prepare(`SELECT r.id,r.lookup_value,r.status,r.created_at,r.admin_note,u.username,u.display_name,u.email,a.account_number FROM password_recovery_requests r JOIN users u ON u.id=r.user_id LEFT JOIN accounts a ON a.user_id=u.id ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 200`).all();
      return response({requests:rows.results||[]},200,request);
    }
    const match=path.match(/^\/api\/admin\/password-recovery\/([^/]+)\/(reset|reject)$/);
    if (method === 'POST' && match) {
      const req=await env.DB.prepare("SELECT * FROM password_recovery_requests WHERE id=? AND status='pending'").bind(match[1]).first();
      if(!req) return response({error:'Pending recovery request not found.'},404,request);
      const d=await body(request);
      if(match[2]==='reject') { await env.DB.prepare("UPDATE password_recovery_requests SET status='rejected',admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(String(d.note||'Rejected by admin').slice(0,250),user.id,req.id).run(); await audit(env,user,'password_recovery_rejected','password_recovery_request',req.id); return response({ok:true,message:'Recovery request rejected.'},200,request); }
      const password=String(d.temporaryPassword||'');
      if(password.length<10 || password.length>128) return response({error:'Temporary password must be 10–128 characters.'},400,request);
      const salt=uid(), hash=await passwordHash(password,salt);
      await env.DB.batch([env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,must_change_password=1 WHERE id=? AND role!='admin'").bind(hash,salt,req.user_id),env.DB.prepare("UPDATE password_recovery_requests SET status='approved',admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind('Password reset by admin. Customer must sign in with the temporary password and change it.',user.id,req.id)]);
      await env.DB.prepare("DELETE FROM sessions WHERE user_id=?").bind(req.user_id).run();
      await audit(env,user,'password_reset_by_admin','user',req.user_id,{requestId:req.id});
      return response({ok:true,message:'Password reset complete. Share the temporary password securely with the customer.'},200,request);
    }
  }

  if (method === "POST" && path === "/api/logout") {
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return response({ ok: true }, 200, request);
  }
  if (!user) return response({ error: "Please log in." }, 401, request);

  // Nova Credit Intelligence + QuickPay: additive tables only; no existing customer data is rewritten.
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS credit_intelligence_subscriptions (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), plan_code TEXT NOT NULL,
    amount INTEGER NOT NULL CHECK(amount>0), starts_at TEXT NOT NULL, expires_at TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active', payment_account_id TEXT REFERENCES accounts(id),
    payment_reference TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_credit_sub_user_expiry ON credit_intelligence_subscriptions(user_id,status,expires_at)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS credit_report_snapshots (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), score INTEGER NOT NULL CHECK(score BETWEEN 300 AND 900),
    report_json TEXT NOT NULL, generated_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_credit_snapshot_user ON credit_report_snapshots(user_id,generated_at DESC)`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quickpay_beneficiaries (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), beneficiary_account_id TEXT NOT NULL REFERENCES accounts(id),
    beneficiary_account_number TEXT NOT NULL, beneficiary_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'cooling',
    verified_at TEXT NOT NULL DEFAULT (datetime('now')), eligible_at TEXT NOT NULL, created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')), UNIQUE(user_id,beneficiary_account_id)
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS quickpay_transfers (
    id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE, user_id TEXT NOT NULL REFERENCES users(id),
    source_account_id TEXT NOT NULL REFERENCES accounts(id), beneficiary_id TEXT NOT NULL REFERENCES quickpay_beneficiaries(id),
    destination_account_id TEXT NOT NULL REFERENCES accounts(id), amount INTEGER NOT NULL, fee INTEGER NOT NULL DEFAULT 0,
    total_debit INTEGER NOT NULL, reference TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL DEFAULT (datetime('now'))
  )`).run();
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS transaction_refunds (id TEXT PRIMARY KEY, original_ledger_id TEXT NOT NULL REFERENCES ledger(id), original_group TEXT, account_id TEXT NOT NULL REFERENCES accounts(id), user_id TEXT NOT NULL REFERENCES users(id), amount INTEGER NOT NULL CHECK(amount>0), reason TEXT NOT NULL, admin_note TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'processed', refund_reference TEXT NOT NULL UNIQUE, idempotency_key TEXT NOT NULL UNIQUE, processed_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL DEFAULT (datetime('now')))`).run();
  await env.DB.prepare('CREATE INDEX IF NOT EXISTS idx_refunds_original ON transaction_refunds(original_ledger_id,created_at)').run();
  await ensureColumn(env,'credit_intelligence_subscriptions','idempotency_key','TEXT');
  await env.DB.prepare('CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_sub_idempotency ON credit_intelligence_subscriptions(idempotency_key) WHERE idempotency_key IS NOT NULL').run();

  if (method==='GET' && path==='/api/credit-intelligence') {
    const loans=await env.DB.prepare(`SELECT COUNT(*) AS total,COALESCE(SUM(CASE WHEN status='active' THEN outstanding_amount ELSE 0 END),0) AS outstanding FROM demo_loans WHERE user_id=?`).bind(user.id).first().catch(()=>({total:0,outstanding:0}));
    const cards=await env.DB.prepare(`SELECT COUNT(*) AS total,COALESCE(SUM(credit_limit),0) AS limits,COALESCE(SUM(outstanding),0) AS outstanding FROM virtual_cards WHERE user_id=? AND status!='closed'`).bind(user.id).first().catch(()=>({total:0,limits:0,outstanding:0}));
    const repayments=await env.DB.prepare(`SELECT COUNT(*) AS total FROM loan_payment_records WHERE borrower_user_id=?`).bind(user.id).first().catch(()=>({total:0}));
    const late=await env.DB.prepare(`SELECT COUNT(*) AS total FROM loan_emi_schedule s JOIN demo_loans l ON l.id=s.loan_id WHERE l.user_id=? AND s.status='pending' AND date(s.due_date)<date('now')`).bind(user.id).first().catch(()=>({total:0}));
    const utilization=Number(cards?.limits||0)>0?Math.min(100,Math.round(Number(cards.outstanding||0)/Number(cards.limits)*100)):0;
    const score=Math.max(300,Math.min(900,Math.round(850-Math.min(260,utilization*2.1)-Math.min(180,Number(late?.total||0)*35)+Math.min(35,Number(repayments?.total||0)*3))));
    const active=await env.DB.prepare(`SELECT id,plan_code,amount,starts_at,expires_at FROM credit_intelligence_subscriptions WHERE user_id=? AND status='active' AND expires_at>datetime('now') ORDER BY expires_at DESC LIMIT 1`).bind(user.id).first();
    const latest=await env.DB.prepare(`SELECT id,score,generated_at FROM credit_report_snapshots WHERE user_id=? ORDER BY generated_at DESC LIMIT 1`).bind(user.id).first();
    return response({score,range:{min:300,max:900},subscription:active||null,reportUnlocked:!!active,latestSnapshot:latest,summary:{loanCount:Number(loans?.total||0),loanOutstanding:Number(loans?.outstanding||0),cardCount:Number(cards?.total||0),cardLimit:Number(cards?.limits||0),cardOutstanding:Number(cards?.outstanding||0),utilization,lateEmis:Number(late?.total||0)}},200,request);
  }
  if (method==='POST' && path==='/api/credit-intelligence/subscribe') {
    const d=await body(request), plans={'1m':{amount:100000,days:30},'6m':{amount:450000,days:180},'12m':{amount:900000,days:365}}, plan=plans[String(d.plan||'')], idem=String(d.idempotencyKey||'');
    if(!plan)return response({error:'Choose a valid subscription plan.'},400,request);
    if(idem.length<12||idem.length>100)return response({error:'A valid payment request key is required. Please retry.'},400,request);
    const already=await env.DB.prepare('SELECT payment_reference,amount,expires_at FROM credit_intelligence_subscriptions WHERE user_id=? AND idempotency_key=?').bind(user.id,idem).first();
    if(already)return response({ok:true,duplicate:true,message:'This subscription payment was already processed.',reference:already.payment_reference,amount:already.amount/100,expiresAt:already.expires_at},200,request);
    const existing=await env.DB.prepare(`SELECT expires_at FROM credit_intelligence_subscriptions WHERE user_id=? AND status='active' AND expires_at>datetime('now') ORDER BY expires_at DESC LIMIT 1`).bind(user.id).first();
    const account=await env.DB.prepare(`SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'`).bind(String(d.accountId||''),user.id).first();
    if(!account)return response({error:'Select one of your active accounts to pay.'},400,request);
    if(Number(account.balance)<plan.amount)return response({error:'Insufficient account balance for this subscription.'},400,request);
    const ref='NCI-'+uid().replaceAll('-','').slice(0,16).toUpperCase(), id=uid(), group=uid();
    const start=existing?.expires_at||new Date().toISOString().slice(0,19).replace('T',' '), end=new Date(new Date(start.replace(' ','T')+'Z').getTime()+plan.days*86400000).toISOString().slice(0,19).replace('T',' ');
    const after=Number(account.balance)-plan.amount;
    await env.DB.batch([
      env.DB.prepare('UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?').bind(plan.amount,account.id,plan.amount),
      env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),account.id,group,'credit_report_subscription',plan.amount,after,`Nova Credit Intelligence ${d.plan} subscription`),
      env.DB.prepare(`INSERT INTO credit_intelligence_subscriptions(id,user_id,plan_code,amount,starts_at,expires_at,payment_account_id,payment_reference,idempotency_key) VALUES(?,?,?,?,?,?,?,?,?)`).bind(id,user.id,String(d.plan),plan.amount,start,end,account.id,ref,idem)
    ]);
    await postTreasury(env,user,'subscription_revenue',plan.amount,`Nova Credit Intelligence subscription ${d.plan}`,'credit_subscription',id,group);
    await audit(env,user,'credit_subscription_purchased','credit_subscription',id,{plan:d.plan,amount:plan.amount,reference:ref});
    return response({ok:true,message:'Credit Intelligence subscription activated.',reference:ref,expiresAt:end},201,request);
  }
  if (method==='GET' && path==='/api/credit-intelligence/report') {
    const sub=await env.DB.prepare(`SELECT id FROM credit_intelligence_subscriptions WHERE user_id=? AND status='active' AND expires_at>datetime('now') ORDER BY expires_at DESC LIMIT 1`).bind(user.id).first();
    if(!sub)return response({error:'Your detailed Credit Report is locked. Purchase or renew a subscription to view it.'},402,request);
    const [loans,cards,loanApps,cardApps,payments,late]=await Promise.all([
      env.DB.prepare(`SELECT loan_number,principal_amount,outstanding_amount,tenure_months,remaining_months,status,created_at FROM demo_loans WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all(),
      env.DB.prepare(`SELECT masked_number,credit_limit,outstanding,status,created_at FROM virtual_cards WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all(),
      env.DB.prepare(`SELECT application_number,requested_amount,sanctioned_amount,status,created_at FROM loan_applications WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all(),
      env.DB.prepare(`SELECT application_number,requested_limit,suggested_limit,sanctioned_limit,status,created_at FROM card_applications WHERE user_id=? ORDER BY created_at DESC`).bind(user.id).all(),
      env.DB.prepare(`SELECT amount,reference,created_at FROM loan_payment_records WHERE borrower_user_id=? ORDER BY created_at DESC LIMIT 100`).bind(user.id).all(),
      env.DB.prepare(`SELECT COUNT(*) AS n FROM loan_emi_schedule s JOIN demo_loans l ON l.id=s.loan_id WHERE l.user_id=? AND s.status='pending' AND date(s.due_date)<date('now')`).bind(user.id).first()
    ]);
    const info=await env.DB.prepare(`SELECT COALESCE(SUM(credit_limit),0) AS lim,COALESCE(SUM(outstanding),0) AS due FROM virtual_cards WHERE user_id=? AND status!='closed'`).bind(user.id).first();
    const utilization=Number(info?.lim||0)>0?Math.min(100,Math.round(Number(info.due||0)/Number(info.lim)*100)):0;
    const score=Math.max(300,Math.min(900,Math.round(850-Math.min(260,utilization*2.1)-Math.min(180,Number(late?.n||0)*35)+Math.min(35,(payments.results||[]).length*3))));
    const report={score,generatedAt:new Date().toISOString(),creditUtilizationPercent:utilization,cardLimit:Number(info?.lim||0),cardOutstanding:Number(info?.due||0),lateEmis:Number(late?.n||0),loans:loans.results||[],cards:cards.results||[],loanApplications:loanApps.results||[],cardApplications:cardApps.results||[],repaymentHistory:payments.results||[],suggestedLoanLimit:Math.max(0,Math.round((Number(info?.lim||0)*0.25)+(Number(loans.results?.length||0)===0?500000:0))),suggestedCardLimit:Math.max(0,Math.round(Number(info?.lim||0)*1.2))};
    const snapshotId=uid(); await env.DB.prepare(`INSERT INTO credit_report_snapshots(id,user_id,score,report_json) VALUES(?,?,?,?)`).bind(snapshotId,user.id,score,JSON.stringify(report)).run();
    return response({report,snapshotId},200,request);
  }
  if (method==='GET' && path==='/api/quickpay/beneficiaries') {
    const rows=await env.DB.prepare(`SELECT b.id,b.beneficiary_account_number,b.beneficiary_name,b.status,b.eligible_at,b.created_at,a.status AS account_status FROM quickpay_beneficiaries b JOIN accounts a ON a.id=b.beneficiary_account_id WHERE b.user_id=? ORDER BY b.created_at DESC`).bind(user.id).all();
    return response({beneficiaries:(rows.results||[]).map(b=>({...b,status:b.account_status!=='active'?'blocked':(new Date(b.eligible_at).getTime()<=Date.now()?'active':'cooling')}))},200,request);
  }
  if (method==='POST' && path==='/api/quickpay/beneficiaries') {
    const d=await body(request), number=String(d.accountNumber||'').trim();
    const dest=await env.DB.prepare(`SELECT a.id,a.user_id,a.account_number,a.status,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=?`).bind(number).first();
    if(!dest||dest.status!=='active'||dest.user_id===user.id)return response({error:'Recipient account not found, inactive, or belongs to you.'},400,request);
    const old=await env.DB.prepare(`SELECT id FROM quickpay_beneficiaries WHERE user_id=? AND beneficiary_account_id=?`).bind(user.id,dest.id).first();
    const id=old?.id||uid();
    await env.DB.prepare(`INSERT INTO quickpay_beneficiaries(id,user_id,beneficiary_account_id,beneficiary_account_number,beneficiary_name,status,eligible_at) VALUES(?,?,?,?,?,'cooling',strftime('%Y-%m-%dT%H:%M:%SZ','now','+10 minutes')) ON CONFLICT(user_id,beneficiary_account_id) DO UPDATE SET beneficiary_account_number=excluded.beneficiary_account_number,beneficiary_name=excluded.beneficiary_name,status='cooling',verified_at=datetime('now'),eligible_at=strftime('%Y-%m-%dT%H:%M:%SZ','now','+10 minutes'),updated_at=datetime('now')`).bind(id,user.id,dest.id,dest.account_number,String(dest.display_name||'Verified NovaBank account holder')).run();
    await audit(env,user,old?'quickpay_beneficiary_reset':'quickpay_beneficiary_added','beneficiary',id,{accountNumber:number,coolingMinutes:10});
    return response({ok:true,message:'Beneficiary verified. A 10-minute cooling period has started.',eligibleAt:new Date(Date.now()+600000).toISOString()},201,request);
  }
  const removeBeneficiary=path.match(/^\/api\/quickpay\/beneficiaries\/([^/]+)$/);
  if(method==='DELETE'&&removeBeneficiary){const r=await env.DB.prepare('DELETE FROM quickpay_beneficiaries WHERE id=? AND user_id=?').bind(removeBeneficiary[1],user.id).run();if(!r.meta?.changes)return response({error:'Beneficiary not found.'},404,request);await audit(env,user,'quickpay_beneficiary_removed','beneficiary',removeBeneficiary[1]);return response({ok:true,message:'Beneficiary removed.'},200,request);}
  if(method==='POST'&&path==='/api/quickpay/transfer'){
    const d=await body(request), amount=Math.round(Number(d.amount||0)*100), key=String(d.idempotencyKey||'');
    if(!Number.isSafeInteger(amount)||amount<100||amount>100000000||key.length<12||key.length>100)return response({error:'Enter a valid amount and unique payment reference.'},400,request);
    const previous=await env.DB.prepare('SELECT reference,amount,fee FROM quickpay_transfers WHERE idempotency_key=? AND user_id=?').bind(key,user.id).first();if(previous)return response({ok:true,duplicate:true,reference:previous.reference,amount:previous.amount/100,fee:previous.fee/100,message:'This payment was already processed.'},200,request);
    const ben=await env.DB.prepare(`SELECT b.*,a.status AS dest_status FROM quickpay_beneficiaries b JOIN accounts a ON a.id=b.beneficiary_account_id WHERE b.id=? AND b.user_id=?`).bind(String(d.beneficiaryId||''),user.id).first();
    if(!ben||ben.dest_status!=='active')return response({error:'Select an active verified beneficiary.'},400,request);
    if(new Date(ben.eligible_at).getTime()>Date.now())return response({error:'Beneficiary cooling period is still active. Try again after the eligible time.'},409,request);
    const source=await env.DB.prepare(`SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'`).bind(String(d.sourceAccountId||''),user.id).first();if(!source||source.id===ben.beneficiary_account_id)return response({error:'Choose a valid source account.'},400,request);
    const fee=amount>5000000?Math.round(amount*0.005):0,total=amount+fee;if(Number(source.balance)<total)return response({error:'Insufficient balance for transfer plus fee.'},400,request);
    const dest=await env.DB.prepare(`SELECT * FROM accounts WHERE id=? AND status='active'`).bind(ben.beneficiary_account_id).first();if(!dest)return response({error:'Beneficiary account is not active.'},400,request);
    const ref='QP-'+uid().replaceAll('-','').slice(0,16).toUpperCase(), group=uid(), after=Number(source.balance)-total, destAfter=Number(dest.balance)+amount, tid=uid();
    try{await env.DB.batch([
      env.DB.prepare('UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?').bind(total,source.id,total),
      env.DB.prepare('UPDATE accounts SET balance=balance+? WHERE id=?').bind(amount,dest.id),
      env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),source.id,group,'transfer_out',amount,after+fee,`Nova QuickPay transfer to ${dest.account_number}`),
      ...(fee?[env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),source.id,group,'quickpay_transfer_fee',fee,after,'Nova QuickPay 0.5% transfer fee')]:[]),
      env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),dest.id,group,'transfer_in',amount,destAfter,`Nova QuickPay received from ${source.account_number}`),
      env.DB.prepare(`INSERT INTO quickpay_transfers(id,idempotency_key,user_id,source_account_id,beneficiary_id,destination_account_id,amount,fee,total_debit,reference) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(tid,key,user.id,source.id,ben.id,dest.id,amount,fee,total,ref)
    ]);}catch(e){const duplicate=await env.DB.prepare('SELECT reference FROM quickpay_transfers WHERE idempotency_key=?').bind(key).first();if(duplicate)return response({ok:true,duplicate:true,reference:duplicate.reference},200,request);throw e;}
    if(fee)await postTreasury(env,user,'quickpay_transfer_fee',fee,'Nova QuickPay 0.5% transfer fee','quickpay_transfer',tid,group);
    await audit(env,user,'quickpay_transfer_completed','quickpay_transfer',tid,{reference:ref,amount,fee,total});await notify(env,dest.user_id,'QuickPay payment received',`N₹${(amount/100).toFixed(2)} received. Reference ${ref}.`);
    return response({ok:true,message:'QuickPay transfer successful.',reference:ref,amount:amount/100,fee:fee/100,totalDebit:total/100,receipt:{reference:ref,beneficiary:ben.beneficiary_name,accountNumber:dest.account_number,amount:amount/100,fee:fee/100,totalDebit:total/100}},200,request);
  }
  if (method==='POST' && path==='/api/change-password') {
    const d=await body(request), currentPassword=String(d.currentPassword||''), newPassword=String(d.newPassword||'');
    if(newPassword.length<12||newPassword.length>128) return response({error:'New password must be 12–128 characters.'},400,request);
    const current=await env.DB.prepare("SELECT password_hash,password_salt FROM users WHERE id=?").bind(user.id).first();
    if(!current || (await passwordHash(currentPassword,current.password_salt))!==current.password_hash) return response({error:'Current password is incorrect.'},403,request);
    if(currentPassword===newPassword) return response({error:'Choose a different password.'},400,request);
    const salt=uid(),hash=await passwordHash(newPassword,salt),token=(request.headers.get('Authorization')||'').replace(/^Bearer\s+/i,'');
    const currentTokenHash=await digest(token),expires=new Date(Date.now()+8*60*60*1000).toISOString();
    await env.DB.prepare("UPDATE users SET password_hash=?,password_salt=?,must_change_password=0 WHERE id=?").bind(hash,salt,user.id).run();
    await env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND token_hash<>?").bind(user.id,currentTokenHash).run();
    await env.DB.prepare("UPDATE sessions SET expires_at=? WHERE token_hash=?").bind(expires,currentTokenHash).run();
    await audit(env,user,'password_changed','user',user.id,{forcedChange:Number(user.must_change_password||0)===1});
    return response({ok:true,message:'Password changed. Other sessions have been signed out.'},200,request);
  }
  if (Number(user.must_change_password||0)===1 && !['/api/me','/api/change-password','/api/logout'].includes(path)) return response({error:'For security, change your temporary password before continuing.'},403,request);
  if (STAFF_ROLES.has(staffRole(user)) && method==='POST' && (
    path==='/api/transfer' || path==='/api/quickpay/transfer' || path==='/api/quickpay/beneficiaries' || path==='/api/loans' || path==='/api/cards' || path==='/api/card-bill/pay' ||
    path==='/api/account-closure-requests' || path==='/api/password-recovery' ||
    /^\/api\/cards\/[^/]+\/(purchase|repay|activate|control-request)$/.test(path) ||
    /^\/api\/loans\/[^/]+\/(accept|repay|closure-request)$/.test(path) || /^\/api\/cards\/[^/]+\/closure-request$/.test(path)
  )) return response({error:'Staff accounts cannot perform customer banking actions.'},403,request);
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS product_closure_requests (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), product_type TEXT NOT NULL CHECK(product_type IN ('loan','card')),
    product_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    amount_paid INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', admin_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT, reviewed_by TEXT REFERENCES users(id), deleted_at TEXT
  )`).run();
  await ensureColumn(env, "product_closure_requests", "deleted_at", "TEXT");
  await ensureColumn(env, "offers", "deleted_at", "TEXT").catch(()=>{});
  await ensureColumn(env, "loan_applications", "deleted_at", "TEXT").catch(()=>{});
  await ensureColumn(env, "card_applications", "deleted_at", "TEXT").catch(()=>{});
  if (method === "GET" && path === "/api/closure-requests") {
    const rows = isSuperAdmin(user)
      ? await env.DB.prepare(`SELECT r.*,u.display_name,u.username FROM product_closure_requests r JOIN users u ON u.id=r.user_id WHERE r.deleted_at IS NULL ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 300`).all()
      : await env.DB.prepare("SELECT * FROM product_closure_requests WHERE user_id=? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return response({requests:rows.results||[]},200,request);
  }
  const loanClosure = path.match(/^\/api\/loans\/([^/]+)\/closure-request$/);
  if (method === "POST" && loanClosure) {
    const loan = await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND user_id=? AND status='active'").bind(loanClosure[1],user.id).first();
    if (!loan) return response({error:"Active demo loan not found."},404,request);
    const duplicate = await env.DB.prepare("SELECT id FROM product_closure_requests WHERE product_type='loan' AND product_id=? AND status='pending'").bind(loan.id).first();
    if (duplicate) return response({error:"A loan closure request is already awaiting admin review."},409,request);
    const amount=Number(loan.outstanding_amount);
    if (!Number.isSafeInteger(amount)||amount<=0) return response({error:"This loan has no outstanding balance. Refresh your dashboard."},400,request);
    const account=await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(loan.account_id,user.id).first();
    if(!account || Number(account.balance)<amount) return response({error:`Full foreclosure requires N₹${(amount/100).toFixed(2)} available in your demo account. Please clear the full outstanding first.`},400,request);
    const reqId=uid(),group=uid(),ledgerId=uid(),after=Number(account.balance)-amount;
    const results=await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND user_id=? AND status='active' AND balance>=?").bind(amount,account.id,user.id,amount),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM accounts WHERE id=? AND balance=?)").bind(ledgerId,account.id,group,"loan_foreclosure_pending",amount,after,`Full demo loan foreclosure payment · ${loan.id}`,account.id,after),
      env.DB.prepare("UPDATE demo_loans SET status='closure_pending',updated_at=datetime('now') WHERE id=? AND user_id=? AND status='active' AND outstanding_amount=? AND EXISTS(SELECT 1 FROM ledger WHERE id=? AND transaction_group=?)").bind(loan.id,user.id,amount,ledgerId,group),
      env.DB.prepare("INSERT INTO product_closure_requests(id,user_id,product_type,product_id,status,amount_paid,note) VALUES(?,?, 'loan',?,'pending',?,?)").bind(reqId,user.id,loan.id,amount,"Full outstanding paid; awaiting admin closure approval")
    ]);
    if(!Number(results?.[0]?.meta?.changes||0)||!Number(results?.[1]?.meta?.changes||0)||!Number(results?.[2]?.meta?.changes||0)) return response({error:"Full payment could not be recorded safely. Refresh and retry."},409,request);
    await postTreasury(env,user,"loan_foreclosure_pending",amount,`Foreclosure payment awaiting approval · ${loan.id}`,"product_closure_request",reqId,group);
    await notify(env,user.id,"Loan closure awaiting review",`Full demo outstanding of N₹${(amount/100).toFixed(2)} has been paid. Admin confirmation is pending.`);
    await audit(env,user,"loan_closure_requested","demo_loan",loan.id,{requestId:reqId,amount});
    return response({ok:true,requestId:reqId,message:`Full payment recorded (N₹${(amount/100).toFixed(2)}). Loan will close after admin approval.`},201,request);
  }
  const cardClosure = path.match(/^\/api\/cards\/([^/]+)\/closure-request$/);
  if (method === "POST" && cardClosure) {
    const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status IN ('active','blocked')").bind(cardClosure[1],user.id).first();
    if(!card) return response({error:"Demo card not found or already closed."},404,request);
    if(Number(card.outstanding)>0) return response({error:`Please clear card dues of N₹${(Number(card.outstanding)/100).toFixed(2)} before requesting closure.`},400,request);
    const duplicate=await env.DB.prepare("SELECT id FROM product_closure_requests WHERE product_type='card' AND product_id=? AND status='pending'").bind(card.id).first();
    if(duplicate) return response({error:"A card closure request is already awaiting admin review."},409,request);
    const reqId=uid(); await env.DB.prepare("INSERT INTO product_closure_requests(id,user_id,product_type,product_id,status,note) VALUES(?,?, 'card',?,'pending','Outstanding is zero; awaiting admin closure approval')").bind(reqId,user.id,card.id).run();
    await notify(env,user.id,"Card closure request submitted","Your demo card closure request is awaiting admin review.");
    await audit(env,user,"card_closure_requested","virtual_card",card.id,{requestId:reqId});
    return response({ok:true,requestId:reqId,message:"Card closure request submitted. It will disappear from Cards & Loans after admin approval."},201,request);
  }
  if (method === "GET" && path === "/api/me") return response({ user }, 200, request);

  // Super Admin: list customers and their demo accounts.
  if (method === "GET" && path === "/api/admin/summary") {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    const [users,accounts,balances,loanStats,cardStats,requestStats,loanApps,cardApps] = await Promise.all([
      env.DB.prepare("SELECT COUNT(*) AS n FROM users WHERE role='customer'").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM accounts").first(),
      env.DB.prepare("SELECT COALESCE(SUM(balance),0) AS n FROM accounts WHERE status='active'").first(),
      env.DB.prepare("SELECT COUNT(*) AS n,COALESCE(SUM(principal_amount),0) AS principal,COALESCE(SUM(outstanding_amount),0) AS outstanding FROM demo_loans").first(),
      env.DB.prepare("SELECT COUNT(*) AS n,COALESCE(SUM(credit_limit),0) AS limits,COALESCE(SUM(outstanding),0) AS outstanding FROM virtual_cards").first(),
      env.DB.prepare("SELECT COUNT(*) AS n,COALESCE(SUM(CASE WHEN type='deposit' THEN amount ELSE 0 END),0) AS deposits,COALESCE(SUM(CASE WHEN type='withdrawal' THEN amount ELSE 0 END),0) AS withdrawals FROM money_requests WHERE status='approved'").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM loan_applications WHERE status IN ('pending','need_documents','verified')").first(),
      env.DB.prepare("SELECT COUNT(*) AS n FROM card_applications WHERE status IN ('pending','need_documents','verified')").first()
    ]);
    const repayments = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM ledger WHERE type IN ('loan_repayment','loan_foreclosure')").first();
    const disbursed = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM ledger WHERE type='loan_disbursement'").first();
    return response({customers:Number(users?.n||0),accounts:Number(accounts?.n||0),customerBalances:Number(balances?.n||0),loanCount:Number(loanStats?.n||0),loanPrincipal:Number(loanStats?.principal||0),loanOutstanding:Number(loanStats?.outstanding||0),cardCount:Number(cardStats?.n||0),cardLimits:Number(cardStats?.limits||0),cardOutstanding:Number(cardStats?.outstanding||0),approvedDeposits:Number(requestStats?.deposits||0),approvedWithdrawals:Number(requestStats?.withdrawals||0),loanDisbursed:Number(disbursed?.n||0),loanRepaid:Number(repayments?.n||0),pendingLoanApplications:Number(loanApps?.n||0),pendingCardApplications:Number(cardApps?.n||0)},200,request);
  }

  if (method === "GET" && path === "/api/admin/customers") {
    if (!hasStaffPermission(user, method, path)) return response({ error: "Insufficient role permission." }, 403, request);
    const q = String(url.searchParams.get("q") || "").trim().slice(0,100);
    const like = `%${q.replace(/[\%_]/g, "\\$&")}%`;
    const branchScoped = staffRole(user)==='branch_manager';
    const sql = `SELECT u.id AS user_id,u.username,u.display_name,u.email,u.role AS user_role,u.status AS user_status,u.created_at AS customer_since,
      a.id AS account_id,a.account_number,a.account_type,a.status AS account_status,a.balance,a.opened_at
      FROM users u LEFT JOIN accounts a ON a.user_id=u.id
      WHERE u.role!='admin' AND (?='' OR u.username LIKE ? ESCAPE '\\' OR u.display_name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\' OR a.account_number LIKE ? ESCAPE '\\')` + (branchScoped ? ` AND a.branch_id=?` : ``) + ` ORDER BY u.created_at DESC LIMIT 250`;
    const rows = branchScoped ? await env.DB.prepare(sql).bind(q,like,like,like,like,user.staff_branch_id||'NB-HQ').all() : await env.DB.prepare(sql).bind(q,like,like,like,like).all();
    return response({ customers: rows.results || [] }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/customer-details") {
    if (!hasStaffPermission(user, method, path)) return response({ error: "Insufficient role permission." }, 403, request);
    const customerId = String(url.searchParams.get("userId") || "").trim();
    if (!customerId) return response({ error: "Customer ID is required." }, 400, request);
    const customer = await env.DB.prepare("SELECT id,username,display_name,email,role,status,created_at FROM users WHERE id=? AND role!='admin'").bind(customerId).first();
    if (!customer) return response({ error: "Customer not found." }, 404, request);
    if (staffRole(user)==='branch_manager') {
      const scope=await env.DB.prepare("SELECT COUNT(*) AS total, SUM(CASE WHEN branch_id=? THEN 1 ELSE 0 END) AS in_branch FROM accounts WHERE user_id=?").bind(user.staff_branch_id||'NB-HQ',customerId).first();
      if (!Number(scope?.in_branch||0) || Number(scope?.total||0)!==Number(scope?.in_branch||0)) return response({error:'Customer is outside your assigned branch scope.'},403,request);
    }
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,account_id TEXT NOT NULL,type TEXT NOT NULL,amount INTEGER NOT NULL,description TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'pending',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),reviewed_at TEXT,reviewed_by TEXT,review_token TEXT)`).run();
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS account_closure_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL,note TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'pending',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),reviewed_at TEXT,reviewed_by TEXT)`).run();
    const [accounts, loans, cards, loanApps, cardApps, tx, closures, money, accountClosures] = await Promise.all([
      env.DB.prepare("SELECT * FROM accounts WHERE user_id=? ORDER BY opened_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM demo_loans WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM virtual_cards WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT id,requested_amount,tenure_months,sanctioned_amount,status,admin_note,created_at,updated_at,deleted_at FROM loan_applications WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT id,requested_limit,sanctioned_limit,status,admin_note,created_at,updated_at,deleted_at FROM card_applications WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT l.* FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.user_id=? ORDER BY l.created_at DESC LIMIT 50").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM product_closure_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM money_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM account_closure_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(customerId).all()
    ]);
    return response({ customer, accounts:accounts.results||[], loans:loans.results||[], cards:cards.results||[], loanApplications:loanApps.results||[], cardApplications:cardApps.results||[], transactions:tx.results||[], closureRequests:closures.results||[], moneyRequests:money.results||[], accountClosureRequests:accountClosures.results||[] },200,request);
  }

  const accountStatusMatch = path.match(/^\/api\/admin\/accounts\/([^/]+)\/status$/);
  if (accountStatusMatch && method === "POST") {
    if (!hasStaffPermission(user, method, path)) return response({ error: "Insufficient role permission." }, 403, request);
    const d = await body(request), status = String(d.status || "");
    if (!['active','frozen'].includes(status)) return response({ error: "Choose active or frozen." }, 400, request);
    const account = await env.DB.prepare("SELECT a.*,u.id AS owner_id,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.id=?").bind(accountStatusMatch[1]).first();
    if (!account) return response({ error: "Account not found." }, 404, request);
    if (user.staff_branch_id && account.branch_id !== (user.staff_branch_id||'NB-HQ')) return response({error:'Account is outside your assigned branch scope.'},403,request);
    if (account.status === status) return response({ ok:true, status, message:`Account is already ${status}.` }, 200, request);
    const note = String(d.note || "").trim().slice(0,250);
    await env.DB.prepare("UPDATE accounts SET status=? WHERE id=?").bind(status, account.id).run();
    await audit(env,user,status==='frozen'?'account_frozen':'account_unfrozen','account',account.id,{accountNumber:account.account_number,ownerId:account.owner_id,note,previousStatus:account.status,newStatus:status});
    await notify(env,account.owner_id,status==='frozen'?'Demo account frozen':'Demo account reactivated',`Your NovaBank demo account ${account.account_number} is now ${status}. ${note}`.trim());
    return response({ ok:true,status,message:`Account ${status==='frozen'?'frozen':'unfrozen'} successfully.` },200,request);
  }

  // Offers are fictional simulator content, managed by admins in the dashboard.
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offer_assignments (
    offer_id TEXT NOT NULL REFERENCES offers(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    assigned_by TEXT REFERENCES users(id), assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY(offer_id,user_id)
  )`).run().catch(()=>{});

  if (path === "/api/offers" && method === "GET") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offers (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, benefit TEXT NOT NULL DEFAULT '', cta_label TEXT NOT NULL DEFAULT 'Explore offer',
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), valid_until TEXT NOT NULL DEFAULT '',
      created_by TEXT REFERENCES users(id), created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    await ensureColumn(env, "offers", "deleted_at", "TEXT");
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM offers WHERE deleted_at IS NULL").first();
    if (!count || Number(count.n) === 0) {
      const seeds = [
        [uid(), "Nova Rewards Card", "Credit Card", "Explore a fictional virtual card with reward points for simulated purchases.", "Up to 5% demo rewards", "View card options", 1, ""],
        [uid(), "Nova Flexi Loan", "Personal Loan", "Try a sample loan application and see a simulated eligibility estimate. Approval is not guaranteed.", "0% demo interest", "Apply for demo loan", 1, ""],
        [uid(), "Smart Shopper Bonus", "Shopping", "Earn fictional reward points by completing learning challenges in the simulator.", "500 demo points", "Explore rewards", 1, ""]
      ];
      await env.DB.batch(seeds.map(x => env.DB.prepare("INSERT INTO offers(id,title,category,description,benefit,cta_label,active,valid_until) VALUES(?,?,?,?,?,?,?,?)").bind(...x)));
    }
    const rows = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT * FROM offers WHERE deleted_at IS NULL ORDER BY created_at DESC").all()
      : await env.DB.prepare("SELECT o.* FROM offers o WHERE o.deleted_at IS NULL AND o.active=1 AND (o.valid_until='' OR o.valid_until>=date('now')) AND (NOT EXISTS(SELECT 1 FROM offer_assignments oa WHERE oa.offer_id=o.id) OR EXISTS(SELECT 1 FROM offer_assignments oa WHERE oa.offer_id=o.id AND oa.user_id=?)) ORDER BY o.created_at DESC").bind(user.id).all();
    return response({ offers: rows.results || [] }, 200, request);
  }

  const offerAssignmentsMatch = path.match(/^\/api\/admin\/offers\/([^/]+)\/assignments$/);
  if (offerAssignmentsMatch && method === "GET") {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    const rows = await env.DB.prepare("SELECT oa.user_id,u.display_name,u.username FROM offer_assignments oa JOIN users u ON u.id=oa.user_id WHERE oa.offer_id=? ORDER BY u.display_name").bind(offerAssignmentsMatch[1]).all();
    return response({users:rows.results||[]},200,request);
  }

  if (path === "/api/admin/offers" && method === "POST") {
    if (!hasStaffPermission(user, method, path)) return response({ error: "Insufficient role permission." }, 403, request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offers (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, benefit TEXT NOT NULL DEFAULT '', cta_label TEXT NOT NULL DEFAULT 'Explore offer',
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), valid_until TEXT NOT NULL DEFAULT '',
      created_by TEXT REFERENCES users(id), created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    await ensureColumn(env, "offers", "deleted_at", "TEXT");
    const d = await body(request);
    const title = String(d.title || '').trim(), category = String(d.category || '').trim(), description = String(d.description || '').trim();
    if (title.length < 3 || title.length > 90 || !["Credit Card","Personal Loan","Shopping","Rewards","Other"].includes(category) || description.length < 8 || description.length > 500)
      return response({ error: "Enter a title, valid category, and description (8–500 characters)." }, 400, request);
    const id = uid();
    await env.DB.prepare("INSERT INTO offers(id,title,category,description,benefit,cta_label,active,valid_until,created_by) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(id, title, category, description, String(d.benefit || '').trim().slice(0,120), String(d.ctaLabel || 'Explore offer').trim().slice(0,40), d.active === false ? 0 : 1, String(d.validUntil || '').trim(), user.id).run();
    await audit(env, user, "offer_created", "offer", id, { title, category });
    return response({ ok: true, id }, 201, request);
  }

  const offerMatch = path.match(/^\/api\/admin\/offers\/([^/]+)$/);
  if (offerMatch && method === "PATCH") {
    if (!hasStaffPermission(user, method, path)) return response({ error: "Insufficient role permission." }, 403, request);
    const d = await body(request), current = await env.DB.prepare("SELECT * FROM offers WHERE id=?").bind(offerMatch[1]).first();
    if (!current) return response({ error: "Offer not found." }, 404, request);
    const active = d.active === undefined ? current.active : (d.active ? 1 : 0);
    await env.DB.prepare("UPDATE offers SET active=?, updated_at=datetime('now') WHERE id=?").bind(active, current.id).run();
    await audit(env, user, active ? "offer_activated" : "offer_deactivated", "offer", current.id, { title: current.title });
    return response({ ok: true, active }, 200, request);
  }

  // Archived loan/card applications remain queryable by Super Admin; source rows are never deleted.
  if (method === "GET" && path === "/api/admin/application-archive") {
    if (!isSuperAdmin(user)) return response({error:"Super Admin permission required."},403,request);
    await ensureApplicationTracking(env);
    await ensureColumn(env,"loan_applications","deleted_at","TEXT");
    await ensureColumn(env,"card_applications","deleted_at","TEXT");
    const [loanRows,cardRows] = await Promise.all([
      env.DB.prepare("SELECT l.id,l.user_id,l.application_number,l.requested_amount AS amount,l.sanctioned_amount AS sanctioned,l.status,l.admin_note,l.created_at,l.updated_at,l.deleted_at,u.display_name,u.username,'loan' AS product_type FROM loan_applications l JOIN users u ON u.id=l.user_id WHERE l.deleted_at IS NOT NULL ORDER BY l.deleted_at DESC LIMIT 300").all(),
      env.DB.prepare("SELECT c.id,c.user_id,c.application_number,c.requested_limit AS amount,c.sanctioned_limit AS sanctioned,c.status,c.admin_note,c.created_at,c.updated_at,c.deleted_at,u.display_name,u.username,'card' AS product_type FROM card_applications c JOIN users u ON u.id=c.user_id WHERE c.deleted_at IS NOT NULL ORDER BY c.deleted_at DESC LIMIT 300").all()
    ]);
    const applications=[...(loanRows.results||[]),...(cardRows.results||[])].sort((a,b)=>String(b.deleted_at||"").localeCompare(String(a.deleted_at||""))).slice(0,500);
    return response({applications},200,request);
  }

  if (method === "GET" && path === "/api/admin/application-search") {
    if(!isSuperAdmin(user)) return response({error:"Super Admin permission required."},403,request);
    await ensureApplicationTracking(env);
    const q=String(url.searchParams.get("q")||"").trim();
    if(q.length<3) return response({error:"Enter at least 3 characters: application number, customer name or account number."},400,request);
    const like=`%${q}%`;
    const [loans,cards]=await Promise.all([
      env.DB.prepare(`SELECT l.id,l.application_number,l.user_id,l.requested_amount,l.sanctioned_amount,l.tenure_months,l.purpose,l.monthly_income,l.monthly_expenses,l.existing_emi,l.eligible_suggestion,l.processing_fee,l.file_charge,l.net_disbursement,l.status,l.admin_note,l.created_at,l.updated_at,l.deleted_at,u.display_name,u.username,u.email,a.account_number,'loan' AS product_type FROM loan_applications l JOIN users u ON u.id=l.user_id LEFT JOIN accounts a ON a.user_id=l.user_id WHERE upper(l.application_number)=upper(?) OR u.display_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR a.account_number LIKE ? ORDER BY l.created_at DESC LIMIT 30`).bind(q,like,like,like,like).all(),
      env.DB.prepare(`SELECT c.id,c.application_number,c.user_id,c.requested_limit,c.sanctioned_limit,c.monthly_income,c.monthly_expenses,c.existing_debt,c.suggested_limit,c.status,c.admin_note,c.created_at,c.updated_at,c.deleted_at,u.display_name,u.username,u.email,a.account_number,'card' AS product_type FROM card_applications c JOIN users u ON u.id=c.user_id LEFT JOIN accounts a ON a.user_id=c.user_id WHERE upper(c.application_number)=upper(?) OR u.display_name LIKE ? OR u.username LIKE ? OR u.email LIKE ? OR a.account_number LIKE ? ORDER BY c.created_at DESC LIMIT 30`).bind(q,like,like,like,like).all()
    ]);
    return response({applications:[...(loans.results||[]),...(cards.results||[])].sort((a,b)=>String(b.created_at).localeCompare(String(a.created_at))).slice(0,50)},200,request);
  }

  // Soft-delete admin catalogue/review records: retain rows for audit and customer history.
  const offerDelete = path.match(/^\/api\/admin\/offers\/([^/]+)$/);
  const loanApplicationDelete = path.match(/^\/api\/admin\/loans\/([^/]+)$/);
  const cardApplicationDelete = path.match(/^\/api\/admin\/cards\/([^/]+)$/);
  if (method === "DELETE" && (offerDelete || loanApplicationDelete || cardApplicationDelete)) {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    const d = await body(request), note = String(d.note||"Removed from active review list").trim().slice(0,240);
    if (offerDelete) {
      await ensureColumn(env,"offers","deleted_at","TEXT");
      const row=await env.DB.prepare("SELECT id,title FROM offers WHERE id=? AND deleted_at IS NULL").bind(offerDelete[1]).first();
      if(!row) return response({error:"Active offer not found."},404,request);
      await env.DB.prepare("UPDATE offers SET deleted_at=datetime('now'),active=0,updated_at=datetime('now') WHERE id=? AND deleted_at IS NULL").bind(row.id).run();
      await audit(env,user,"offer_soft_deleted","offer",row.id,{title:row.title,note});
      return response({ok:true,message:"Offer removed from active catalogue; audit history retained."},200,request);
    }
    const isLoan=!!loanApplicationDelete, table=isLoan?"loan_applications":"card_applications", id=(isLoan?loanApplicationDelete:cardApplicationDelete)[1];
    await ensureColumn(env,table,"deleted_at","TEXT");
    const row=await env.DB.prepare(`SELECT id,user_id,status FROM ${table} WHERE id=? AND deleted_at IS NULL`).bind(id).first();
    if(!row) return response({error:"Active review request not found."},404,request);
    await env.DB.prepare(`UPDATE ${table} SET deleted_at=datetime('now'),updated_at=datetime('now') WHERE id=? AND deleted_at IS NULL`).bind(id).run();
    await audit(env,user,isLoan?"loan_application_soft_deleted":"card_application_soft_deleted",isLoan?"loan_application":"card_application",id,{status:row.status,note});
    await notify(env,row.user_id,isLoan?"Loan review item archived":"Card review item archived","Your reviewed request was archived from the admin queue. Its history remains available.");
    return response({ok:true,message:"Removed from active review list; audit history retained."},200,request);
  }

  if (method === 'GET' && path === '/api/admin/refunds') {
    if (!user || !isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const q=String(new URL(request.url).searchParams.get('q')||'').trim();
    const like=`%${q}%`;
    const rows=await env.DB.prepare(`SELECT l.id AS ledger_id,l.transaction_group,l.account_id,l.type,l.amount,l.description,l.created_at,l.balance_after,a.account_number,u.id AS user_id,u.display_name,u.username,COALESCE((SELECT SUM(r.amount) FROM transaction_refunds r WHERE r.original_ledger_id=l.id),0) AS refunded_amount FROM ledger l JOIN accounts a ON a.id=l.account_id JOIN users u ON u.id=a.user_id WHERE l.amount>0 AND l.type IN ('transfer_out','credit_report_subscription','quickpay_transfer_fee') AND (?='' OR l.id LIKE ? OR l.transaction_group LIKE ? OR a.account_number LIKE ? OR u.display_name LIKE ? OR u.username LIKE ?) ORDER BY l.created_at DESC LIMIT 250`).bind(q,like,like,like,like,like).all();
    const refunds=await env.DB.prepare(`SELECT r.*,u.display_name,u.username,a.account_number FROM transaction_refunds r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id ORDER BY r.created_at DESC LIMIT 250`).all();
    return response({transactions:rows.results||[],refunds:refunds.results||[]},200,request);
  }
  if (method === 'POST' && path === '/api/admin/refunds') {
    if (!user || !isSuperAdmin(user)) return response({error:'Super Admin permission required.'},403,request);
    const d=await body(request), ledgerId=String(d.ledgerId||''), reason=String(d.reason||'').trim().slice(0,240), note=String(d.adminNote||'').trim().slice(0,240), idem=String(d.idempotencyKey||'');
    const rupees=Number(d.amount), amount=Math.round(rupees*100);
    if(!ledgerId||!reason||!Number.isSafeInteger(amount)||amount<=0||idem.length<12)return response({error:'Select an original transaction, enter a valid refund amount and reason.'},400,request);
    const prior=await env.DB.prepare('SELECT refund_reference,amount FROM transaction_refunds WHERE idempotency_key=?').bind(idem).first();
    if(prior)return response({ok:true,duplicate:true,reference:prior.refund_reference,amount:prior.amount/100,message:'This refund was already processed.'},200,request);
    const original=await env.DB.prepare(`SELECT l.*,a.user_id,a.status AS account_status FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE l.id=? AND l.amount>0 AND l.type IN ('transfer_out','credit_report_subscription','quickpay_transfer_fee')`).bind(ledgerId).first();
    if(!original)return response({error:'Eligible original debit transaction not found.'},404,request);
    const total=await env.DB.prepare('SELECT COALESCE(SUM(amount),0) AS n FROM transaction_refunds WHERE original_ledger_id=?').bind(ledgerId).first();
    const remaining=Number(original.amount)-Number(total?.n||0);
    if(amount>remaining)return response({error:`Refund exceeds refundable balance. Maximum available: ₹${(remaining/100).toFixed(2)}.`},400,request);
    if(original.account_status!=='active')return response({error:'Customer account is not active; refund cannot be posted.'},409,request);
    const refundId=uid(), ref='RF-'+uid().replaceAll('-','').slice(0,16).toUpperCase(), group=uid();
    const current=await env.DB.prepare('SELECT balance FROM accounts WHERE id=?').bind(original.account_id).first();
    const newBalance=Number(current.balance)+amount;
    let treasuryRefund=null;
    if(['credit_report_subscription','quickpay_transfer_fee'].includes(original.type)) {
      await ensureTreasury(env);
      const treasuryNow=await env.DB.prepare('SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger').first();
      if(Number(treasuryNow?.balance||0)<amount)return response({error:'Treasury has insufficient available funds to support this revenue refund. No refund was posted.'},409,request);
      treasuryRefund={before:Number(treasuryNow?.balance||0),after:Number(treasuryNow?.balance||0)-amount};
    }
    const batch=[
      env.DB.prepare('UPDATE accounts SET balance=balance+? WHERE id=?').bind(amount,original.account_id),
      env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),original.account_id,group,'refund_credit',amount,newBalance,`Refund for ${original.id}: ${reason}`),
      env.DB.prepare(`INSERT INTO transaction_refunds(id,original_ledger_id,original_group,account_id,user_id,amount,reason,admin_note,refund_reference,idempotency_key,processed_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)`).bind(refundId,original.id,original.transaction_group,original.account_id,original.user_id,amount,reason,note,ref,idem,user.id)
    ];
    if(treasuryRefund) {
      const treasuryGroup=uid(), treasuryId=uid();
      batch.push(env.DB.prepare(`INSERT INTO treasury_ledger(id,transaction_group,type,amount,balance_after,description,source_type,source_id,actor_user_id,reference) VALUES(?,?,?,?,?,?,?,?,?,?)`).bind(treasuryId,treasuryGroup,'revenue_refund',-amount,treasuryRefund.after,`Revenue refund for original transaction ${original.id}`,'transaction_refund',refundId,user.id,`refund-${ref}`));
      batch.push(env.DB.prepare(`UPDATE treasury_accounts SET current_balance=?,updated_at=datetime('now') WHERE id='nova-treasury-main'`).bind(treasuryRefund.after));
    }
    if(['transfer_out'].includes(original.type)) {
      const incoming=await env.DB.prepare(`SELECT l.*,a.balance AS recipient_balance,a.user_id AS recipient_user FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE l.transaction_group=? AND l.type='transfer_in' LIMIT 1`).bind(original.transaction_group).first();
      if(!incoming)return response({error:'Matching recipient credit could not be found; refund blocked for safety.'},409,request);
      if(Number(incoming.recipient_balance)<amount)return response({error:'Recipient account has insufficient available balance for this transfer reversal.'},409,request);
      batch.push(env.DB.prepare('UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?').bind(amount,incoming.account_id,amount));
      batch.push(env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)`).bind(uid(),incoming.account_id,group,'refund_debit',amount,Number(incoming.recipient_balance)-amount,`Reversal of transfer ${original.id}`));
    }
    try {
      await env.DB.batch(batch);
    } catch(e) {
      const dup=await env.DB.prepare('SELECT refund_reference,amount FROM transaction_refunds WHERE idempotency_key=?').bind(idem).first();
      if(dup)return response({ok:true,duplicate:true,reference:dup.refund_reference,amount:dup.amount/100},200,request);
      throw e;
    }
    await audit(env,user,'transaction_refund_processed','transaction_refund',refundId,{originalLedgerId:original.id,amount,reason,adminNote:note,reference:ref});
    await notify(env,original.user_id,'NovaBank refund processed',`N₹${(amount/100).toFixed(2)} refund credited. Reference ${ref}.`);
    return response({ok:true,message:'Refund processed and credited to customer account.',reference:ref,amount:amount/100,balance:newBalance/100},200,request);
  }

  if (method === "GET" && path === "/api/admin/treasury") {
    if(!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await ensureTreasury(env);
    const account=await env.DB.prepare("SELECT * FROM treasury_accounts WHERE id='nova-treasury-main'").first();
    const rows=await env.DB.prepare("SELECT * FROM treasury_ledger ORDER BY created_at DESC LIMIT 500").all();
    const totals=await env.DB.prepare("SELECT COALESCE(SUM(CASE WHEN amount>0 THEN amount ELSE 0 END),0) AS inflow,COALESCE(SUM(CASE WHEN amount<0 THEN -amount ELSE 0 END),0) AS outflow,COALESCE(SUM(amount),0) AS balance,COUNT(*) AS entries,COALESCE(SUM(CASE WHEN type IN ('loan_processing_fee','loan_file_charge','card_joining_fee','credit_card_transfer_fee','merchant_commission','subscription_revenue','quickpay_transfer_fee','service_fee') THEN amount ELSE 0 END),0) AS revenue FROM treasury_ledger").first();
    const breakdown=await env.DB.prepare("SELECT type,COALESCE(SUM(amount),0) AS amount,COUNT(*) AS entries FROM treasury_ledger GROUP BY type ORDER BY ABS(SUM(amount)) DESC").all();
    account.current_balance=Number(totals?.balance||0);
    return response({account,transactions:rows.results||[],totals:totals||{},breakdown:breakdown.results||[]},200,request);
  }
  if (method === "POST" && path === "/api/admin/treasury/fund") {
    if (!user || !isSuperAdmin(user)) return response({error:"Super Admin permission required."},403,request);
    await ensureTreasury(env);
    const d = await body(request);
    const kind = String(d.kind || "manual_funding");
    const amountRupees = Number(d.amount);
    const source = String(d.source || "").trim().slice(0,100);
    const remarks = String(d.remarks || "").trim().slice(0,240);
    if (!Number.isFinite(amountRupees) || amountRupees <= 0 || amountRupees > 1000000000 || Math.round(amountRupees * 100) <= 0)
      return response({error:"Enter a valid funding amount greater than zero (maximum ₹1,00,00,00,000)."},400,request);
    if (!remarks) return response({error:"Remarks are required for the audit trail."},400,request);
    if (!['opening_balance','manual_funding'].includes(kind)) return response({error:"Unsupported funding type."},400,request);
    const opening = await env.DB.prepare("SELECT COUNT(*) AS n FROM treasury_ledger WHERE type='opening_balance'").first();
    if (kind === 'opening_balance' && Number(opening?.n || 0) > 0)
      return response({error:"Opening balance has already been recorded. Use Admin Manual Funding for additional funds."},409,request);
    const existing = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger").first();
    const balance = Number(existing?.balance || 0), amount = Math.round(amountRupees * 100), after = balance + amount;
    const reference = `NVT-${crypto.randomUUID().replace(/-/g,'').slice(0,16).toUpperCase()}`;
    const entryId = uid();
    try {
      await env.DB.batch([
        env.DB.prepare("INSERT INTO treasury_ledger(id,transaction_group,type,amount,balance_after,description,source_type,source_id,actor_user_id,reference) VALUES(?,?,?,?,?,?,?,?,?,?)")
          .bind(entryId, reference, kind, amount, after, remarks, source || (kind === 'opening_balance' ? 'Opening Balance' : 'Admin Manual Funding'), reference, user.id, reference),
        env.DB.prepare("UPDATE treasury_accounts SET current_balance=?,updated_at=datetime('now') WHERE id='nova-treasury-main'").bind(after)
      ]);
      await audit(env,user,kind === 'opening_balance' ? 'treasury_opening_balance_added' : 'treasury_manual_funding_added','treasury_account','nova-treasury-main',{reference,amount,source,remarks,balanceAfter:after});
      return response({ok:true,reference,balance:after,message:`Funding recorded. Reference: ${reference}`},201,request);
    } catch (e) {
      console.error('Treasury funding error:',e);
      return response({error:"Funding could not be recorded. Refresh Treasury and check the ledger before retrying."},500,request);
    }
  }

  if (method === "GET" && path === "/api/accounts") {
    const rows = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT a.*,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id ORDER BY a.opened_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM accounts WHERE user_id=?").bind(user.id).all();
    return response({ accounts: rows.results || [] }, 200, request);
  }
  if (method === "GET" && path === "/api/transactions") {
    const accountId = url.searchParams.get("accountId");
    let q;

    // Customers may load recent activity before selecting an account.
    // In that case, return transactions for all accounts they own.
    if ((isSuperAdmin(user) || staffRole(user)==='auditor') && !accountId) {
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id ORDER BY l.created_at DESC LIMIT 500"
      );
    } else if (!accountId && !isSuperAdmin(user) && staffRole(user)!=='auditor') {
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.user_id=? ORDER BY l.created_at DESC LIMIT 200"
      ).bind(user.id);
    } else if (isSuperAdmin(user) || staffRole(user)==='auditor') {
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.id=? ORDER BY l.created_at DESC LIMIT 200"
      ).bind(accountId);
    } else {
      const owner = await env.DB.prepare(
        "SELECT id FROM accounts WHERE id=? AND user_id=?"
      ).bind(accountId, user.id).first();
      if (!owner) return response({ error: "Account not found." }, 404, request);
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.id=? AND a.user_id=? ORDER BY l.created_at DESC LIMIT 200"
      ).bind(accountId, user.id);
    }

    const rows = await q.all();
    return response({ transactions: rows.results || [] }, 200, request);
  }
  // Legacy direct balance-changing endpoints are intentionally disabled. Customers must request admin review.
  if (method === "POST" && (path === "/api/deposit" || path === "/api/withdraw")) {
    return response({ error: "Direct balance changes are disabled. Submit a deposit or withdrawal request for admin approval." }, 403, request);
  }

  if (path === "/api/money-requests" && method === "GET") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    const rows = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT r.*,u.display_name,u.username,a.account_number FROM money_requests r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 300").all()
      : await env.DB.prepare("SELECT r.*,a.account_number FROM money_requests r JOIN accounts a ON a.id=r.account_id WHERE r.user_id=? ORDER BY r.created_at DESC LIMIT 100").bind(user.id).all();
    return response({ requests: rows.results || [] }, 200, request);
  }
  if (path === "/api/money-requests" && method === "POST") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    const d = await body(request), amount = Math.round(Number(d.amount) * 100), type = String(d.type || '');
    if (!['deposit','withdrawal'].includes(type) || !Number.isSafeInteger(amount) || amount < 100 || amount > 100000000)
      return response({ error: "Choose deposit or withdrawal and enter an amount from N₹1 to N₹1,000,000." }, 400, request);
    const account = await env.DB.prepare("SELECT id,balance,account_number FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(String(d.accountId||''),user.id).first();
    if (!account) return response({ error: "Active demo account not found." }, 404, request);
    if (type === 'withdrawal' && Number(account.balance) < amount) return response({ error: "Requested withdrawal exceeds your current demo balance." }, 400, request);
    const id = "MR-" + uid().replace(/-/g,'').slice(0,12).toUpperCase();
    const description = String(d.description || (type==='deposit'?'Demo deposit request':'Demo withdrawal request')).trim().slice(0,100);
    await env.DB.prepare("INSERT INTO money_requests(id,user_id,account_id,type,amount,description) VALUES(?,?,?,?,?,?)").bind(id,user.id,account.id,type,amount,description).run();
    await notify(env,user.id,"Money request submitted",`${type==='deposit'?'Deposit':'Withdrawal'} request ${id} for N₹${(amount/100).toFixed(2)} is awaiting admin review. Your balance has not changed.`);
    await audit(env,user,"money_request_submitted","money_request",id,{type,amount,accountId:account.id});
    return response({ok:true,requestId:id,message:"Request submitted for admin approval. Your balance has not changed."},201,request);
  }
  if (method === "GET" && path === "/api/admin/money-requests") {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    await ensureColumn(env, "money_requests", "deleted_at", "TEXT");
    const archived = new URL(request.url).searchParams.get("archived") === "1";
    const branchScoped=staffRole(user)==='branch_manager';
    const where = `${archived ? "r.deleted_at IS NOT NULL" : "r.deleted_at IS NULL"}` + (branchScoped ? ` AND a.branch_id=?` : ``);
    const query=`SELECT r.*,u.display_name,u.username,a.account_number FROM money_requests r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id WHERE ${where} ORDER BY CASE r.status WHEN 'pending' THEN 0 WHEN 'processing' THEN 1 ELSE 2 END,r.created_at DESC LIMIT 300`;
    const rows=branchScoped?await env.DB.prepare(query).bind(user.staff_branch_id||'NB-HQ').all():await env.DB.prepare(query).all();
    return response({requests:rows.results||[]},200,request);
  }
  const moneyArchive = path.match(/^\/api\/admin\/money-requests\/([^/]+)\/archive$/);
  if (moneyArchive && method === "POST") {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    await ensureColumn(env, "money_requests", "deleted_at", "TEXT");
    const d=await body(request), note=String(d.note||"Hidden from active queue").trim().slice(0,250);
    const row=await env.DB.prepare("SELECT r.id,r.user_id,r.status,r.type,r.amount,a.branch_id FROM money_requests r JOIN accounts a ON a.id=r.account_id WHERE r.id=? AND r.deleted_at IS NULL").bind(moneyArchive[1]).first();
    if(row && user.staff_branch_id && row.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Request is outside your assigned branch scope.'},403,request);
    if(!row) return response({error:"Active money request not found."},404,request);
    if(!["approved","rejected"].includes(row.status)) return response({error:"Only reviewed requests can be archived. Approve or reject it first."},409,request);
    const changed=await env.DB.prepare("UPDATE money_requests SET deleted_at=datetime('now') WHERE id=? AND deleted_at IS NULL AND status IN ('approved','rejected')").bind(row.id).run();
    if(!Number(changed.meta?.changes||0)) return response({error:"Request changed while archiving. Refresh the queue."},409,request);
    await audit(env,user,"money_request_archived","money_request",row.id,{status:row.status,type:row.type,amount:row.amount,note});
    return response({ok:true,message:"Reviewed request hidden from active list; transaction and audit history are preserved."},200,request);
  }
  const moneyReview = path.match(/^\/api\/admin\/money-requests\/([^/]+)\/review$/);
  if (moneyReview && method === "POST") {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    const d=await body(request), status=String(d.status||''), note=String(d.note||'').trim().slice(0,250);
    if(!['approved','rejected'].includes(status)) return response({error:'Choose approve or reject.'},400,request);
    const r=await env.DB.prepare("SELECT r.*,a.branch_id FROM money_requests r JOIN accounts a ON a.id=r.account_id WHERE r.id=?").bind(moneyReview[1]).first();
    if(r && user.staff_branch_id && r.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Request is outside your assigned branch scope.'},403,request);
    if(!r) return response({error:'Money request not found.'},404,request);
    if(r.status!=='pending') return response({error:`This request has already been ${r.status}.`},409,request);
    if(status==='rejected') {
      const result=await env.DB.prepare("UPDATE money_requests SET status='rejected',admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(note,user.id,r.id).run();
      if(!result.meta?.changes) return response({error:'Request was already processed. Refresh the queue.'},409,request);
      await notify(env,r.user_id,'Money request rejected',`Request ${r.id} was rejected. ${note}`);
      await audit(env,user,'money_request_rejected','money_request',r.id,{type:r.type,amount:r.amount,note});
      return response({ok:true,message:`Request ${r.id} rejected. Balance unchanged.`},200,request);
    }
    const account=await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND status='active'").bind(r.account_id).first();
    if(!account) return response({error:'Linked account is not active; request cannot be approved.'},400,request);
    if(r.type==='withdrawal' && Number(account.balance)<Number(r.amount)) return response({error:'Insufficient current balance. Reject this request or ask customer to submit a new amount.'},400,request);
    const token=uid(), group=uid(), ledgerId=uid(), amount=Number(r.amount);
    const nextBalance=r.type==='deposit'?Number(account.balance)+amount:Number(account.balance)-amount;
    const updateBalance=r.type==='deposit'
      ? env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND status='active' AND EXISTS(SELECT 1 FROM money_requests WHERE id=? AND status='processing' AND review_token=?)").bind(amount,account.id,r.id,token)
      : env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND status='active' AND balance>=? AND EXISTS(SELECT 1 FROM money_requests WHERE id=? AND status='processing' AND review_token=?)").bind(amount,account.id,amount,r.id,token);
    // D1 batch makes the balance, ledger, and request status changes atomic.
    const results=await env.DB.batch([
      env.DB.prepare("UPDATE money_requests SET status='processing',review_token=?,admin_note=?,reviewed_by=? WHERE id=? AND status='pending'").bind(token,note,user.id,r.id),
      updateBalance,
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) SELECT ?,?,?,?, ?,?,? WHERE EXISTS(SELECT 1 FROM money_requests WHERE id=? AND status='processing' AND review_token=?) AND EXISTS(SELECT 1 FROM accounts WHERE id=? AND balance=?)").bind(ledgerId,account.id,group,r.type==='deposit'?'deposit':'withdrawal',amount,nextBalance,`${r.type==='deposit'?'Admin-approved demo deposit':'Admin-approved demo withdrawal'} · ${r.id}`,r.id,token,account.id,nextBalance),
      env.DB.prepare("UPDATE money_requests SET status='approved',reviewed_at=datetime('now'),review_token=NULL WHERE id=? AND status='processing' AND review_token=? AND EXISTS(SELECT 1 FROM ledger WHERE id=? AND transaction_group=?)").bind(r.id,token,ledgerId,group)
    ]);
    const changed=Number(results?.[1]?.meta?.changes||0), ledgerChanged=Number(results?.[2]?.meta?.changes||0), approvedChanged=Number(results?.[3]?.meta?.changes||0);
    if(!changed || !ledgerChanged || !approvedChanged) {
      await env.DB.prepare("UPDATE money_requests SET status='pending',review_token=NULL,admin_note='Approval could not be completed; please review again.' WHERE id=? AND status='processing' AND review_token=?").bind(r.id,token).run();
      return response({error:'Approval could not be completed safely. Refresh and retry; no completed approval was recorded.'},409,request);
    }
    await postTreasury(env,user,r.type==='deposit'?'customer_deposit':'customer_withdrawal',r.type==='deposit'?amount:-amount,`${r.type==='deposit'?'Customer deposit':'Customer withdrawal'} · ${r.id}`,'money_request',r.id,group);
    await notify(env,r.user_id,'Money request approved',`${r.type==='deposit'?'Deposit':'Withdrawal'} request ${r.id} approved. N₹${(amount/100).toFixed(2)} demo balance ${r.type==='deposit'?'credited':'debited'}.`);
    await audit(env,user,'money_request_approved','money_request',r.id,{type:r.type,amount,accountId:r.account_id,transactionGroup:group,note});
    return response({ok:true,message:`Request ${r.id} approved. Demo balance updated to N₹${(nextBalance/100).toFixed(2)}.`},200,request);
  }

  if (method === "GET" && path === "/api/recipient-lookup") {
    const number=String(url.searchParams.get("accountNumber")||"").trim();
    if(!/^NB[0-9A-Za-z]{6,20}$/i.test(number)) return response({error:"Enter a valid demo account number."},400,request);
    const recipient=await env.DB.prepare("SELECT a.account_number,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.status='active'").bind(number).first();
    if(!recipient) return response({error:"No active demo account matches that number."},404,request);
    return response({ok:true,accountNumber:recipient.account_number,recipientName:recipient.display_name},200,request);
  }
  if (method === "GET" && path === "/api/card-bill") {
    await ensureCardColumns(env);
    await reconcileZeroCardOutstanding(env);
    const last4=String(url.searchParams.get("last4")||"").trim().toUpperCase();
    if(!/^[A-Z0-9]{4}$/.test(last4)) return response({error:"Enter the last four characters of a demo card."},400,request);
    const rows=await env.DB.prepare(`SELECT c.id,c.user_id,c.masked_number,c.credit_limit,c.outstanding,c.status,c.demo_number,u.display_name,u.username
      FROM virtual_cards c JOIN users u ON u.id=c.user_id
      WHERE (upper(substr(COALESCE(c.demo_number,''),-4))=? OR upper(substr(replace(COALESCE(c.masked_number,''),' ',''),-4))=?)
      ORDER BY c.outstanding DESC,c.created_at DESC LIMIT 50`).bind(last4,last4).all();
    const matches=(rows.results||[]).map(c=>({cardId:c.id,cardName:"Nova Rewards Card",maskedNumber:c.masked_number||(`•••• •••• •••• ${last4}`),cardholderName:c.display_name||c.username||"Cardholder",username:c.username,outstanding:Number(c.outstanding||0),availableCredit:Math.max(0,Number(c.credit_limit||0)-Number(c.outstanding||0)),status:c.status}));
    if(!matches.length) return response({error:"No registered demo credit card matches those last four characters."},404,request);
    return response({ok:true,last4,matches},200,request);
  }
  if (method === "POST" && path === "/api/card-bill/pay") {
    await ensureCardColumns(env); await ensureCardTransactions(env); await ensureTreasury(env); await ensureCardBillPayments(env);
    const d=await body(request), amount=Math.round(Number(d.amount)*100), cardId=String(d.cardId||""), accountId=String(d.accountId||""), key=String(d.idempotencyKey||"");
    if(!cardId||!accountId||!Number.isSafeInteger(amount)||amount<100) return response({error:"Choose a card, your own source account, and a payment amount of at least N₹1."},400,request);
    if(!/^[A-Za-z0-9._:-]{16,100}$/.test(key)) return response({error:"A valid payment confirmation reference is required. Please refresh and try again."},400,request);
    const previous=await env.DB.prepare("SELECT status,transaction_group,amount FROM card_bill_payments WHERE idempotency_key=? AND payer_user_id=?").bind(key,user.id).first();
    if(previous?.status==='completed') return response({ok:true,alreadyProcessed:true,transactionId:previous.transaction_group,message:`This payment was already processed once. No duplicate debit was made. Amount: N₹${(Number(previous.amount)/100).toFixed(2)}.`},200,request);
    if(previous) return response({error:"This payment reference is already in use. Refresh the bill and start a new confirmation."},409,request);
    const account=await env.DB.prepare("SELECT id,user_id,account_number,balance,status FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(accountId,user.id).first();
    if(!account) return response({error:"Select one of your own active NovaBank accounts."},403,request);
    const card=await env.DB.prepare("SELECT id,user_id,masked_number,credit_limit,outstanding,status FROM virtual_cards WHERE id=?").bind(cardId).first();
    if(!card) return response({error:"Registered demo credit card not found."},404,request);
    if(amount>Number(card.outstanding||0)) return response({error:"Payment cannot exceed the latest card outstanding. Fetch the bill again."},400,request);
    if(Number(account.balance)<amount) return response({error:"Insufficient balance in the selected source account."},400,request);
    const paymentId=uid(), group=uid(), ledgerId=uid(), cardTxId=uid(), treasuryId=uid(), auditId=uid();
    const description=`Credit-card bill payment · ${card.masked_number||card.id} · paid by ${user.username}`;
    let results;
    try { results=await env.DB.batch([
      env.DB.prepare(`INSERT INTO card_bill_payments(id,idempotency_key,transaction_group,payer_user_id,card_owner_user_id,account_id,card_id,amount,account_balance_before,card_outstanding_before,status)
        SELECT ?,?,?,?,?,?,?,?,?,?,'pending' FROM accounts a JOIN virtual_cards c ON c.id=?
        WHERE a.id=? AND a.user_id=? AND a.status='active' AND a.balance>=? AND c.outstanding>=?
        ON CONFLICT(idempotency_key) DO NOTHING`).bind(paymentId,key,group,user.id,card.user_id,account.id,card.id,amount,Number(account.balance),Number(card.outstanding),card.id,account.id,user.id,amount,amount),
      env.DB.prepare(`UPDATE accounts SET balance=balance-? WHERE id=? AND user_id=? AND status='active' AND balance=? AND EXISTS(SELECT 1 FROM card_bill_payments p WHERE p.id=? AND p.status='pending' AND p.account_id=accounts.id)`).bind(amount,account.id,user.id,Number(account.balance),paymentId),
      env.DB.prepare(`UPDATE virtual_cards SET outstanding=outstanding-? WHERE id=? AND outstanding=? AND EXISTS(SELECT 1 FROM card_bill_payments p WHERE p.id=? AND p.status='pending' AND p.card_id=virtual_cards.id) AND EXISTS(SELECT 1 FROM accounts a JOIN card_bill_payments p ON p.account_id=a.id WHERE p.id=? AND a.balance=p.account_balance_before-p.amount)`).bind(amount,card.id,Number(card.outstanding),paymentId,paymentId),
      env.DB.prepare(`INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description)
        SELECT ?,a.id,?,'card_bill_payment',?,a.balance,? FROM accounts a JOIN card_bill_payments p ON p.account_id=a.id JOIN virtual_cards c ON c.id=p.card_id
        WHERE p.id=? AND p.status='pending' AND a.balance=p.account_balance_before-p.amount AND c.outstanding=p.card_outstanding_before-p.amount`).bind(ledgerId,group,amount,description,paymentId),
      env.DB.prepare(`INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description)
        SELECT ?,c.id,c.user_id,?,'bill_payment',?,? FROM virtual_cards c JOIN card_bill_payments p ON p.card_id=c.id JOIN accounts a ON a.id=p.account_id
        WHERE p.id=? AND p.status='pending' AND a.balance=p.account_balance_before-p.amount AND c.outstanding=p.card_outstanding_before-p.amount`).bind(cardTxId,group,amount,`Bill payment received · payer ${user.username} · source ${account.account_number}`,paymentId),
      env.DB.prepare(`INSERT INTO treasury_ledger(id,transaction_group,type,amount,balance_after,description,source_type,source_id,actor_user_id,reference)
        SELECT ?,?, 'card_bill_payment',?,COALESCE((SELECT SUM(amount) FROM treasury_ledger),0)+?,?,'virtual_card',?, ?,?
        WHERE EXISTS(SELECT 1 FROM card_bill_payments p JOIN accounts a ON a.id=p.account_id JOIN virtual_cards c ON c.id=p.card_id WHERE p.id=? AND p.status='pending' AND a.balance=p.account_balance_before-p.amount AND c.outstanding=p.card_outstanding_before-p.amount)
        ON CONFLICT(reference) WHERE reference IS NOT NULL DO NOTHING`).bind(treasuryId,group,amount,amount,description,card.id,user.id,`card-bill-${paymentId}`,paymentId),
      env.DB.prepare("UPDATE treasury_accounts SET current_balance=COALESCE((SELECT SUM(amount) FROM treasury_ledger),0),updated_at=datetime('now') WHERE id='nova-treasury-main' AND EXISTS(SELECT 1 FROM treasury_ledger WHERE id=? AND transaction_group=?)").bind(treasuryId,group),
      env.DB.prepare("UPDATE card_bill_payments SET status='completed' WHERE id=? AND status='pending'").bind(paymentId),
      env.DB.prepare(`INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,details) SELECT ?,?,'demo_card_bill_payment','virtual_card',?,? WHERE EXISTS(SELECT 1 FROM card_bill_payments WHERE id=? AND status='completed')`).bind(auditId,user.id,card.id,JSON.stringify({amount,accountId:account.id,payerUserId:user.id,cardOwnerUserId:card.user_id,transactionGroup:group}),paymentId)
    ]); } catch (e) {
      console.error("CARD_BILL_PAYMENT_BATCH_FAILED", e instanceof Error ? e.message : String(e));
      return response({error:"Payment could not be completed safely. No partial payment was committed; fetch the bill and try again.",reference:"CARD_BILL_PAYMENT_BATCH_FAILED"},409,request);
    }
    const inserted=Number(results?.[0]?.meta?.changes||0);
    const completed=await env.DB.prepare("SELECT status,amount,transaction_group FROM card_bill_payments WHERE id=? AND idempotency_key=?").bind(paymentId,key).first();
    if(!inserted||completed?.status!=='completed') {
      const existing=await env.DB.prepare("SELECT status,transaction_group,amount FROM card_bill_payments WHERE idempotency_key=? AND payer_user_id=?").bind(key,user.id).first();
      if(existing?.status==='completed') return response({ok:true,alreadyProcessed:true,transactionId:existing.transaction_group,message:"This payment was already processed. No duplicate debit was made."},200,request);
      return response({error:"Payment was not completed. No successful payment was recorded; fetch the latest bill and try again."},409,request);
    }
    const remaining=Number(card.outstanding)-amount;
    await notify(env,card.user_id,"Credit card bill payment received",`N₹${(amount/100).toFixed(2)} was paid toward card ${card.masked_number||card.id}. Remaining demo outstanding: N₹${(remaining/100).toFixed(2)}.`);
    return response({ok:true,message:`Credit card bill payment successful. Remaining outstanding: N₹${(remaining/100).toFixed(2)}.`,transactionId:group,remainingOutstanding:remaining},200,request);
  }
  if (method === "POST" && path === "/api/account-closure-requests") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS account_closure_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending',note TEXT NOT NULL DEFAULT '',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),reviewed_at TEXT,reviewed_by TEXT REFERENCES users(id))`).run();
    const existing=await env.DB.prepare("SELECT id FROM account_closure_requests WHERE user_id=? AND status='pending'").bind(user.id).first();
    if(existing)return response({error:"An account closure request is already pending."},409,request);
    const id=uid();await env.DB.prepare("INSERT INTO account_closure_requests(id,user_id) VALUES(?,?)").bind(id,user.id).run();
    await audit(env,user,"account_closure_requested","account",user.id,{requestId:id});
    return response({ok:true,message:"Account closure request submitted for Super Admin review.",requestId:id},201,request);
  }
  if (method === "GET" && path === "/api/account-closure-requests") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS account_closure_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending',note TEXT NOT NULL DEFAULT '',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),reviewed_at TEXT,reviewed_by TEXT REFERENCES users(id))`).run();
    const rows=isSuperAdmin(user)?await env.DB.prepare("SELECT r.*,u.display_name,u.username FROM account_closure_requests r JOIN users u ON u.id=r.user_id ORDER BY r.created_at DESC").all():staffRole(user)==='branch_manager'?await env.DB.prepare("SELECT DISTINCT r.*,u.display_name,u.username FROM account_closure_requests r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.user_id=r.user_id WHERE a.branch_id=? ORDER BY r.created_at DESC").bind(user.staff_branch_id||'NB-HQ').all():await env.DB.prepare("SELECT * FROM account_closure_requests WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return response({requests:rows.results||[]},200,request);
  }
  const accountClosureReview = path.match(/^\/api\/admin\/account-closure-requests\/([^/]+)\/review$/);
  if (method === "POST" && accountClosureReview) {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS account_closure_requests (id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),status TEXT NOT NULL DEFAULT 'pending',note TEXT NOT NULL DEFAULT '',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),reviewed_at TEXT,reviewed_by TEXT REFERENCES users(id))`).run();
    const d=await body(request), status=String(d.status||"");
    if(!["approved","rejected"].includes(status)) return response({error:"Choose approve or reject."},400,request);
    const req=await env.DB.prepare("SELECT * FROM account_closure_requests WHERE id=? AND status='pending'").bind(accountClosureReview[1]).first();
    if(!req) return response({error:"Pending account closure request not found."},404,request);
    if(staffRole(user)==='branch_manager') { const scope=await env.DB.prepare("SELECT COUNT(*) AS total,SUM(CASE WHEN branch_id=? THEN 1 ELSE 0 END) AS in_branch FROM accounts WHERE user_id=?").bind(user.staff_branch_id||'NB-HQ',req.user_id).first(); if(!Number(scope?.in_branch||0)||Number(scope?.total||0)!==Number(scope?.in_branch||0)) return response({error:'Customer is outside your assigned branch scope.'},403,request); }
    if(status==="approved") {
      const activeLoan=await env.DB.prepare("SELECT id FROM demo_loans WHERE user_id=? AND status='active' AND outstanding_amount>0 LIMIT 1").bind(req.user_id).first();
      const activeCard=await env.DB.prepare("SELECT id FROM virtual_cards WHERE user_id=? AND status='active' AND outstanding>0 LIMIT 1").bind(req.user_id).first();
      if(activeLoan||activeCard) return response({error:"Account cannot close while a demo loan or credit card has outstanding dues."},409,request);
      await env.DB.batch([
        env.DB.prepare("UPDATE accounts SET status='closed' WHERE user_id=? AND status='active'").bind(req.user_id),
        env.DB.prepare("UPDATE account_closure_requests SET status='approved',admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(String(d.note||"").slice(0,250),user.id,req.id)
      ]);
    } else await env.DB.prepare("UPDATE account_closure_requests SET status='rejected',admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(String(d.note||"").slice(0,250),user.id,req.id).run();
    await audit(env,user,"account_closure_reviewed","account_closure_request",req.id,{status,note:String(d.note||"").slice(0,250)});
    await notify(env,req.user_id,"Account closure request updated",`Your demo account closure request was ${status}.`);
    return response({ok:true,message:`Account closure request ${status}.`},200,request);
  }
  if (method === "POST" && path === "/api/transfer") {
    const d = await body(request), amount = Math.round(Number(d.amount) * 100);
    if (!Number.isSafeInteger(amount) || amount < 100 || amount > 100000000) return response({ error: "Transfer amount must be between N₹1 and N₹1,000,000." }, 400, request);
    const dest = await env.DB.prepare("SELECT * FROM accounts WHERE account_number=? AND status='active'").bind(String(d.toAccountNumber || "").trim()).first();
    if (!dest || dest.user_id===user.id) return response({ error: "Check recipient account. Transfers to your own demo account are not supported." }, 400, request);
    if (String(d.paymentMethod||"account")==="credit_card") {
      await ensureCardColumns(env);
      const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status='active'").bind(String(d.fromCreditCardId||""),user.id).first();
      if(!card) return response({error:"Select an active linked demo credit card."},400,request);
      const fee=Math.round(amount*0.009), total=amount+fee, available=Number(card.credit_limit||0)-Number(card.outstanding||0);
      if(total>available) return response({error:`Insufficient available demo credit. Transfer plus 0.9% fee requires N₹${(total/100).toFixed(2)}.`},400,request);
      const nextOutstanding=Number(card.outstanding||0)+total, nextDest=Number(dest.balance)+amount, group=uid(), creditId=uid();
      const results=await env.DB.batch([
        env.DB.prepare("UPDATE virtual_cards SET outstanding=? WHERE id=? AND outstanding=? AND credit_limit-outstanding>=?").bind(nextOutstanding,card.id,card.outstanding,total),
        env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND status='active'").bind(amount,dest.id),
        env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(creditId,dest.id,group,"transfer_in",amount,nextDest,"Demo credit-card-funded transfer" )
      ]);
      if(results.some(x=>!Number(x?.meta?.changes||0))) return response({error:"Transfer could not be completed safely. Refresh and retry."},409,request);
      await ensureCardTransactions(env);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),card.id,user.id,group,"funded_transfer",amount,`Credit-card-funded transfer to ${dest.account_number}`),
        env.DB.prepare("INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),card.id,user.id,group,"transfer_fee",fee,"0.9% demo transfer fee")
      ]);
      await postTreasury(env,user,"credit_card_funded_transfer",0,`Credit-card-funded transfer principal N₹${(amount/100).toFixed(2)}`,"transaction",group,group);
      await postTreasury(env,user,"credit_card_transfer_fee",fee,"0.9% demo credit-card transfer fee","transaction",group,group);
      await audit(env,user,"demo_credit_card_transfer","transaction",group,{amount,fee,total,cardId:card.id,toAccount:dest.id});
      await notify(env,dest.user_id,"Money received",`N₹${(amount/100).toFixed(2)} demo transfer received.`);
      return response({ok:true,message:`Demo transfer sent. 0.9% fee: N₹${(fee/100).toFixed(2)}. Card outstanding increased by N₹${(total/100).toFixed(2)}.`,transactionId:group,fee:fee/100,total:total/100},200,request);
    }
    const source = await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(d.fromAccountId, user.id).first();
    if (!source || source.id === dest.id) return response({ error: "Check source and recipient account." }, 400, request);
    if (source.balance < amount) return response({ error: "Insufficient demo balance." }, 400, request);
    // MVP batch pattern; concurrency/ledger invariants require a dedicated hardening pass before any public launch.
    const group = uid(), debitId = uid(), creditId = uid();
    const debitBalance = source.balance - amount, creditBalance = dest.balance + amount;
    await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?").bind(amount, source.id, amount),
      env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=?").bind(amount, dest.id),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(debitId, source.id, group, "transfer_out", amount, debitBalance, "Demo transfer to " + dest.account_number),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(creditId, dest.id, group, "transfer_in", amount, creditBalance, "Demo transfer from " + source.account_number)
    ]);
    await postTreasury(env,user,"internal_transfer",0,`Internal demo transfer · ${source.account_number} → ${dest.account_number}`,"transaction",group,group);
    await audit(env, user, "demo_transfer", "transaction", group, { amount, from: source.id, to: dest.id });
    await notify(env, dest.user_id, "Money received", `N₹${(amount/100).toFixed(2)} demo transfer received.`);
    return response({ ok: true, status: "SUCCESS", message: "Demo transfer completed successfully.", transactionId: group, reference: group, amount: amount / 100, fee: 0, totalDebit: amount / 100 }, 200, request);
  }
  if (method === "GET" && path === "/api/application-track") {
    await ensureApplicationTracking(env);
    const applicationNumber=String(url.searchParams.get("applicationNumber")||"").trim().toUpperCase();
    if(!/^NB-(LN|CC)-[0-9]{8}-[A-F0-9]{8}$/.test(applicationNumber)) return response({error:"Enter a valid NovaBank application number."},400,request);
    const loan=await env.DB.prepare("SELECT id,application_number,'loan' AS product_type,requested_amount AS requested,sanctioned_amount AS sanctioned,status,admin_note,processing_fee,file_charge,net_disbursement,tenure_months,created_at,updated_at FROM loan_applications WHERE application_number=? AND user_id=?").bind(applicationNumber,user.id).first();
    const card=loan?null:await env.DB.prepare("SELECT id,application_number,'card' AS product_type,requested_limit AS requested,sanctioned_limit AS sanctioned,status,admin_note,created_at,updated_at FROM card_applications WHERE application_number=? AND user_id=?").bind(applicationNumber,user.id).first();
    const item=loan||card;
    if(!item) return response({error:"No application found for this number in your account."},404,request);
    let schedule=[];
    if(loan){
      const active=await env.DB.prepare("SELECT id FROM demo_loans WHERE application_id=? AND user_id=?").bind(loan.id,user.id).first();
      if(active) schedule=(await env.DB.prepare("SELECT installment_no,due_date,amount,status,paid_at FROM loan_emi_schedule WHERE loan_id=? ORDER BY installment_no").bind(active.id).all()).results||[];
    }
    const cardRecord=card?await env.DB.prepare("SELECT masked_number,credit_limit,outstanding,status,activation_pending FROM virtual_cards WHERE id=? AND user_id=?").bind(card.id,user.id).first():null;
    return response({application:item,emiSchedule:schedule,card:cardRecord},200,request);
  }

  if (method === "POST" && path === "/api/loans") {
    const d = await body(request), amount = Math.round(Number(d.requestedAmount)*100), tenure = Number(d.tenureMonths);
    if (!Number.isSafeInteger(amount) || amount < 10000 || amount > 500000000 || !Number.isInteger(tenure) || tenure < 1 || tenure > 120 || String(d.purpose||"").trim().length < 3)
      return response({ error: "Enter a valid demo loan amount, tenure (1–120 months), and purpose." }, 400, request);
    const income = Math.max(0, Math.round(Number(d.monthlyIncome||0)*100)), expenses = Math.max(0, Math.round(Number(d.monthlyExpenses||0)*100)), emi = Math.max(0, Math.round(Number(d.existingEmi||0)*100));
    const eligible = Math.max(0, Math.min(amount, Math.round(Math.max(0, income-expenses-emi)*tenure*0.3)));
    await ensureApplicationTracking(env);
    await ensureColumn(env,"loan_applications","credit_score_snapshot","INTEGER NOT NULL DEFAULT 0");
    const creditSnapshot=await calculateInternalCreditScore(env,user.id);
    const id = uid(), applicationNumber = newApplicationNumber("NB-LN", id);
    await env.DB.prepare("INSERT INTO loan_applications(id,user_id,requested_amount,tenure_months,purpose,monthly_income,monthly_expenses,existing_emi,eligible_suggestion,application_number,credit_score_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
      .bind(id,user.id,amount,tenure,String(d.purpose).trim(),income,expenses,emi,eligible,applicationNumber,creditSnapshot.score).run();
    await audit(env,user,"loan_application_submitted","loan_application",id,{applicationNumber});
    await notify(env,user.id,"Loan application submitted",`Your loan application ${applicationNumber} has been submitted and is awaiting review.`);
    return response({ ok:true, id, applicationNumber, suggestedEligibility: eligible/100, message:"Demo application submitted for review." },201,request);
  }
  if (method === "GET" && path === "/api/loans") {
    await ensureApplicationTracking(env);
    await ensureColumn(env,"loan_applications","deleted_at","TEXT");
    const rows = (isSuperAdmin(user)||staffRole(user)==='loan_officer')
      ? await env.DB.prepare("SELECT l.*,u.display_name,u.username FROM loan_applications l JOIN users u ON u.id=l.user_id WHERE l.deleted_at IS NULL AND l.status IN ('pending','need_documents','verified') ORDER BY l.created_at DESC").all()
      : await env.DB.prepare("SELECT * FROM loan_applications WHERE user_id=? AND status NOT IN ('rejected','closed') ORDER BY created_at DESC").bind(user.id).all();
    return response({ applications: rows.results || [] },200,request);
  }
  if (method === "POST" && path === "/api/cards") {
    await ensureCardColumns(env);
    const d = await body(request);
    const income=Math.round(Number(d.monthlyIncome||0)*100), expenses=Math.round(Number(d.monthlyExpenses||0)*100);
    const emi=Math.round(Number(d.existingEmi||0)*100), debt=Math.round(Number(d.existingDebt||0)*100), loanOutstanding=Math.round(Number(d.loanOutstanding||0)*100);
    if (![income,expenses,emi,debt,loanOutstanding].every(n=>Number.isSafeInteger(n)&&n>=0) || income>10000000000 || expenses>10000000000 || emi>10000000000 || debt>100000000000 || loanOutstanding>100000000000 || expenses>income*10)
      return response({error:"Enter valid non-negative financial details."},400,request);
    const monthlySurplus=Math.max(0,income-expenses-emi);
    // Fictional, configurable-style heuristic: 3x monthly surplus, capped at N₹200,000.
    // Existing outstanding informs the risk adjustment; this is not a real credit decision.
    const suggested=Math.max(0,Math.min(20000000,Math.round(monthlySurplus*3*Math.max(0.25,1-Math.min(0.75,(debt+loanOutstanding)/Math.max(income*12,1))))));
    await ensureApplicationTracking(env);
    await ensureColumn(env,"card_applications","credit_score_snapshot","INTEGER NOT NULL DEFAULT 0");
    const creditSnapshot=await calculateInternalCreditScore(env,user.id);
    const id=uid(), applicationNumber=newApplicationNumber("NB-CC",id);
    // card_applications.requested_limit has a CHECK(requested_limit > 0).
    // The customer is applying for bank assessment rather than requesting a fixed limit,
    // so persist the calculated suggested limit; use the smallest positive minor unit
    // only when the assessment estimate is zero, preserving compatibility with existing D1.
    const requestedLimit = Math.max(1, suggested);
    await env.DB.prepare("INSERT INTO card_applications(id,user_id,requested_limit,monthly_income,monthly_expenses,existing_debt,suggested_limit,existing_emi,loan_outstanding,application_number,credit_score_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
      .bind(id,user.id,requestedLimit,income,expenses,debt,suggested,emi,loanOutstanding,applicationNumber,creditSnapshot.score).run();
    await audit(env,user,"card_application_submitted","card_application",id,{applicationNumber,income,expenses,existingEmi:emi,existingCardDebt:debt,loanOutstanding,suggestedLimit:suggested});
    await notify(env,user.id,"Credit card application submitted",`Your credit card application ${applicationNumber} has been submitted and is awaiting review.`);
    return response({ok:true,id,applicationNumber,suggestedLimit:suggested/100,message:"Demo card application submitted for bank assessment."},201,request);
  }
  if (method === "GET" && path === "/api/cards") {
    await ensureApplicationTracking(env);
    await ensureCardColumns(env);
    await ensureColumn(env,"card_applications","deleted_at","TEXT");
    const rows = (isSuperAdmin(user)||staffRole(user)==='credit_officer')
      ? await env.DB.prepare("SELECT c.*,u.display_name,u.username FROM card_applications c JOIN users u ON u.id=c.user_id WHERE c.deleted_at IS NULL AND c.status IN ('pending','need_documents','verified') ORDER BY c.created_at DESC").all()
      : await env.DB.prepare("SELECT * FROM card_applications WHERE user_id=? AND status NOT IN ('rejected','closed') ORDER BY created_at DESC").bind(user.id).all();
    return response({ applications: rows.results || [] },200,request);
  }
  if (method === "GET" && path === "/api/products") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    await ensureBranchOperations(env);
    await reconcileZeroCardOutstanding(env, isSuperAdmin(user) ? null : user.id);
    const loans = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT * FROM demo_loans ORDER BY created_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM demo_loans WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    const cards = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT * FROM virtual_cards ORDER BY created_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM virtual_cards WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    await ensureCardTransactions(env);
    const cardTransactions = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT * FROM card_transactions ORDER BY created_at DESC LIMIT 300").all()
      : await env.DB.prepare("SELECT * FROM card_transactions WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    await ensureApplicationTracking(env);
    const emiSchedules = isSuperAdmin(user)
      ? await env.DB.prepare("SELECT s.*,l.user_id,l.application_id FROM loan_emi_schedule s JOIN demo_loans l ON l.id=s.loan_id ORDER BY s.due_date DESC LIMIT 1000").all()
      : await env.DB.prepare("SELECT s.*,l.user_id,l.application_id FROM loan_emi_schedule s JOIN demo_loans l ON l.id=s.loan_id WHERE l.user_id=? ORDER BY s.installment_no").bind(user.id).all();
    return response({ loans: loans.results || [], cards: cards.results || [], cardTransactions: cardTransactions.results || [], emiSchedules: emiSchedules.results || [] }, 200, request);
  }

  const acceptLoanMatch = path.match(/^\/api\/loans\/([^/]+)\/accept$/);
  if (method === "POST" && acceptLoanMatch) {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    const loan = await env.DB.prepare("SELECT * FROM loan_applications WHERE id=? AND user_id=?").bind(acceptLoanMatch[1], user.id).first();
    if (!loan) return response({ error: "Loan application not found." }, 404, request);
    if (loan.status !== "approved" || !loan.sanctioned_amount || loan.sanctioned_amount <= 0) return response({ error: "Only an approved loan with a sanctioned amount can be accepted." }, 400, request);
    const exists = await env.DB.prepare("SELECT id FROM demo_loans WHERE application_id=?").bind(loan.id).first();
    if (exists) return response({ error: "This demo loan has already been activated." }, 409, request);
    const account = await env.DB.prepare("SELECT * FROM accounts WHERE user_id=? AND status='active' ORDER BY opened_at LIMIT 1").bind(user.id).first();
    if (!account) return response({ error: "No active demo account is available." }, 400, request);
    await ensureApplicationTracking(env);
    await ensureColumn(env,"demo_loans","processing_fee","INTEGER NOT NULL DEFAULT 0");
    await ensureColumn(env,"demo_loans","file_charge","INTEGER NOT NULL DEFAULT 0");
    await ensureColumn(env,"demo_loans","net_disbursed","INTEGER NOT NULL DEFAULT 0");
    await ensureBranchOperations(env);
    const id=uid(), loanNumber=`NVL-${new Date().getFullYear()}-${id.replace(/-/g,'').slice(0,10).toUpperCase()}`, amount=Number(loan.sanctioned_amount), tenure=Number(loan.tenure_months), processingFee=Number(loan.processing_fee||Math.round(amount*0.05)), fileCharge=Number(loan.file_charge||110000), netDisbursement=Number(loan.net_disbursement||amount-processingFee-fileCharge), monthly=Math.floor(amount/tenure), group=uid();
    if(netDisbursement<=0 || netDisbursement!==amount-processingFee-fileCharge) return response({error:"The approved loan fee calculation is invalid. Please ask the admin to review the offer again."},409,request);
    await ensureTreasury(env);
    const treasuryFunds = await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger").first();
    const availableTreasury = Number(treasuryFunds?.balance || 0);
    if (availableTreasury < amount) return response({error:`Insufficient Treasury Funds. Available N₹${(availableTreasury/100).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2})}; required N₹${(amount/100).toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2})}. Add funds before disbursement.`},409,request);
    const schedule=[]; let allocated=0;
    for(let n=1;n<=tenure;n++){const installment=n===tenure?amount-allocated:monthly;allocated+=installment;schedule.push({id:uid(),n,due:emiDueDate(n),amount:installment});}
    await env.DB.batch([
      env.DB.prepare("INSERT INTO demo_loans(id,application_id,user_id,account_id,principal_amount,outstanding_amount,tenure_months,remaining_months,monthly_payment,status,processing_fee,file_charge,net_disbursed,loan_number) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?,?,?)").bind(id,loan.id,user.id,account.id,amount,amount,tenure,tenure,Math.floor(amount/tenure),processingFee,fileCharge,netDisbursement,loanNumber),
      env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND user_id=?").bind(netDisbursement,account.id,user.id),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),account.id,group,"loan_disbursement",netDisbursement,Number(account.balance)+netDisbursement,`Net demo loan disbursement · ${loan.application_number||loan.id}`),
      env.DB.prepare("UPDATE loan_applications SET status='disbursed',updated_at=datetime('now') WHERE id=? AND user_id=? AND status='approved'").bind(loan.id,user.id),
      ...schedule.map(s=>env.DB.prepare("INSERT INTO loan_emi_schedule(id,loan_id,application_id,installment_no,due_date,amount) VALUES(?,?,?,?,?,?)").bind(s.id,id,loan.id,s.n,s.due,s.amount))
    ]);
    await postTreasury(env,user,"loan_disbursement",-netDisbursement,`Net loan disbursement · ${id}`,"demo_loan",id,group);
    await postTreasury(env,user,"loan_processing_fee",processingFee,`5% demo loan processing fee · ${id}`,"demo_loan",id,group);
    await postTreasury(env,user,"loan_file_charge",fileCharge,`Demo loan file charge · ${id}`,"demo_loan",id,group);
    await notify(env,user.id,"Demo loan activated",`Loan ${loanNumber} disbursed. Sanction: N₹${(amount/100).toFixed(2)}; processing fee: N₹${(processingFee/100).toFixed(2)}; file charge: N₹${(fileCharge/100).toFixed(2)}; net credited: N₹${(netDisbursement/100).toFixed(2)}. Your ${tenure}-month, 0% demo EMI schedule is ready.`);
    await audit(env,user,"demo_loan_disbursed","demo_loan",id,{applicationId:loan.id,applicationNumber:loan.application_number,amount,tenure,processingFee,fileCharge,netDisbursement,interestRate:0});
    return response({ok:true,loanNumber,message:`Demo loan disbursed. Loan Account Number: ${loanNumber}. Net amount credited: N₹${(netDisbursement/100).toFixed(2)} after 5% processing fee and ₹1,100 file charge. EMI schedule created for ${tenure} months.`},200,request);
  }

  // Public-to-authenticated loan lookup reveals only the minimum details needed to pay a loan.
  if (method === 'GET' && path === '/api/loan-lookup') {
    await ensureBranchOperations(env);
    const loanNumber=String(url.searchParams.get('loanNumber')||'').trim().toUpperCase();
    if(!/^NVL-[0-9]{4}-[A-F0-9]{8,10}$/.test(loanNumber)) return response({error:'Enter a valid NovaBank Loan Account Number.'},400,request);
    const loan=await env.DB.prepare(`SELECT l.loan_number,l.principal_amount,l.outstanding_amount,l.monthly_payment,l.tenure_months,l.remaining_months,l.status,l.created_at,u.display_name,a.account_number FROM demo_loans l JOIN users u ON u.id=l.user_id JOIN accounts a ON a.id=l.account_id WHERE l.loan_number=?`).bind(loanNumber).first();
    if(!loan) return response({error:'Loan account not found.'},404,request);
    const schedule=await env.DB.prepare("SELECT installment_no,due_date,amount,paid_amount,status FROM loan_emi_schedule WHERE loan_id=(SELECT id FROM demo_loans WHERE loan_number=?) ORDER BY installment_no").bind(loanNumber).all();
    const next=(schedule.results||[]).find(x=>x.status!=='paid');
    return response({loan:{loanNumber:loan.loan_number,borrower:loan.display_name,accountMasked:`••••${String(loan.account_number).slice(-4)}`,principal:loan.principal_amount,outstanding:loan.outstanding_amount,monthlyEmi:loan.monthly_payment,tenureMonths:loan.tenure_months,remainingMonths:loan.remaining_months,status:loan.status,nextDue:next?.due_date||null,nextDueAmount:next?Math.max(0,Number(next.amount)-Number(next.paid_amount||0)):0},schedule:schedule.results||[]},200,request);
  }
  const oldRepayMatch=path.match(/^\/api\/loans\/([^/]+)\/repay$/);
  const customerLoanPay=method==='POST' && path==='/api/loan-payments';
  const branchLoanPay=method==='POST' && path==='/api/branch/loan-payment';
  if ((method==='POST' && oldRepayMatch) || customerLoanPay || branchLoanPay) {
    await ensureBranchOperations(env); await ensureTreasury(env);
    const staffPayment=branchLoanPay;
    if(staffPayment && !(await branchAllowed(user,method,path))) return response({error:'Branch teller permission required.'},403,request);
    if(!staffPayment && STAFF_ROLES.has(staffRole(user))) return response({error:'Staff must use the Branch Counter.'},403,request);
    const d=await body(request);
    let loan;
    if(oldRepayMatch) loan=await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND user_id=? AND status='active'").bind(oldRepayMatch[1],user.id).first();
    else loan=await env.DB.prepare("SELECT * FROM demo_loans WHERE loan_number=? AND status='active'").bind(String(d.loanNumber||'').trim().toUpperCase()).first();
    if(!loan) return response({error:'Active loan account not found.'},404,request);
    const schedule=(await env.DB.prepare("SELECT * FROM loan_emi_schedule WHERE loan_id=? AND status IN ('pending') ORDER BY installment_no").bind(loan.id).all()).results||[];
    const firstDue=schedule.find(x=>x.status!=='paid');
    const amount=Math.round(Number(d.amount??(oldRepayMatch?Math.max(0,Number(firstDue?.amount||loan.monthly_payment)-Number(firstDue?.paid_amount||0))/100:0))*100), methodType=staffPayment?String(d.paymentMethod||'cash'):'account', idem=String(d.idempotencyKey||(oldRepayMatch?`legacy-${uid()}`:''));
    if(!['cash','account'].includes(methodType)||!Number.isSafeInteger(amount)||amount<100||amount>Number(loan.outstanding_amount)) return response({error:'Enter a valid payment method and an amount from NVR 1 up to the current loan outstanding.'},400,request);
    if(!/^[A-Za-z0-9._:-]{16,100}$/.test(idem)) return response({error:'Payment reference is missing. Refresh and retry.'},400,request);
    const previous=await env.DB.prepare('SELECT reference,amount FROM loan_payment_records WHERE idempotency_key=?').bind(idem).first();
    if(previous) return response({ok:true,alreadyProcessed:true,reference:previous.reference,message:'This payment was already recorded; no duplicate debit was made.'},200,request);
    let payerAccount=null;
    if(methodType==='account') {
      const accountNumber=String(d.payerAccountNumber||'').trim().toUpperCase();
      if(oldRepayMatch) payerAccount=await env.DB.prepare("SELECT a.*,u.id AS owner_id,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.id=? AND a.user_id=? AND a.status='active'").bind(loan.account_id,user.id).first();
      else if(staffPayment) payerAccount=await env.DB.prepare("SELECT a.*,u.id AS owner_id,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.status='active'").bind(accountNumber).first();
      else payerAccount=await env.DB.prepare("SELECT a.*,u.id AS owner_id,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.user_id=? AND a.status='active'").bind(accountNumber,user.id).first();
      if(!payerAccount) return response({error:staffPayment?'Payer account not found or inactive.':'Select one of your own active NovaBank accounts.'},403,request);
      if(staffPayment && user.staff_branch_id && payerAccount.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Payer account is outside your assigned branch.'},403,request);
      if(Number(payerAccount.balance)<amount) return response({error:'Insufficient payer account balance.'},409,request);
    }
    let remaining=amount; const allocations=[];
    for(const emi of schedule){ if(remaining<=0) break; const due=Math.max(0,Number(emi.amount)-Number(emi.paid_amount||0)); if(!due) continue; const applied=Math.min(due,remaining); allocations.push({id:emi.id,installmentNo:emi.installment_no,paidAfter:Number(emi.paid_amount||0)+applied,amount:Number(emi.amount),applied}); remaining-=applied; }
    if(remaining>0) return response({error:'No pending EMI schedule is available for this loan. Contact the simulator administrator.'},409,request);
    const outstanding=Number(loan.outstanding_amount)-amount, group=uid(), paymentId=uid(), reference=`NVP-${crypto.randomUUID().replace(/-/g,'').slice(0,16).toUpperCase()}`;
    const operations=[];
    if(payerAccount) {
      operations.push(env.DB.prepare('UPDATE accounts SET balance=balance-? WHERE id=? AND status=\'active\' AND balance>=?').bind(amount,payerAccount.id,amount));
      operations.push(env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),payerAccount.id,group,'loan_repayment',amount,Number(payerAccount.balance)-amount,`Loan EMI payment for ${loan.loan_number}`));
    }
    operations.push(env.DB.prepare("UPDATE demo_loans SET outstanding_amount=?,remaining_months=?,status=?,updated_at=datetime('now') WHERE id=? AND outstanding_amount=? AND status='active'").bind(outstanding,schedule.filter(e=>{const a=allocations.find(x=>x.id===e.id);return a? a.paidAfter<a.amount : e.status!=='paid';}).length,outstanding===0?'closed':'active',loan.id,Number(loan.outstanding_amount)));
    for(const a of allocations) operations.push(env.DB.prepare("UPDATE loan_emi_schedule SET paid_amount=?,status=?,paid_at=CASE WHEN ?='paid' THEN datetime('now') ELSE paid_at END,transaction_group=? WHERE id=? AND status IN ('pending')").bind(a.paidAfter,a.paidAfter>=a.amount?'paid':'pending',a.paidAfter>=a.amount?'paid':'pending',group,a.id));
    operations.push(env.DB.prepare("INSERT INTO loan_payment_records(id,idempotency_key,loan_id,loan_number,borrower_user_id,payer_user_id,payer_account_id,payment_method,amount,reference,actor_user_id,allocations_json) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)").bind(paymentId,idem,loan.id,loan.loan_number,loan.user_id,payerAccount?.owner_id||null,payerAccount?.id||null,methodType,amount,reference,user.id,JSON.stringify(allocations)));
    await env.DB.batch(operations);
    await postTreasury(env,user,'loan_repayment',amount,`Loan repayment · ${loan.loan_number} · ${methodType}`,'loan_payment',paymentId,group);
    if(outstanding===0) await env.DB.prepare("UPDATE loan_applications SET status='closed',updated_at=datetime('now') WHERE id=?").bind(loan.application_id).run();
    await notify(env,loan.user_id,'Loan payment received',`A payment of NVR ${(amount/100).toFixed(2)} was received for loan ${loan.loan_number}. Remaining outstanding: NVR ${(outstanding/100).toFixed(2)}.`);
    await audit(env,user,'loan_payment_received','demo_loan',loan.id,{loanNumber:loan.loan_number,amount,paymentMethod:methodType,payerUserId:payerAccount?.owner_id||null,reference,allocations});
    return response({ok:true,reference,loanNumber:loan.loan_number,outstanding,message:`Loan payment received. Reference: ${reference}. Remaining outstanding: NVR ${(outstanding/100).toFixed(2)}.`},200,request);
  }

  // Branch Counter: account lookup, cash deposit/withdrawal and credit-card collection.
  if(path.startsWith('/api/branch/')) {
    if(!(await branchAllowed(user,method,path))) return response({error:'Branch Counter permission required.'},403,request);
    await ensureBranchOperations(env);
    if(method==='GET' && path==='/api/branch/account-lookup') {
      const number=String(url.searchParams.get('accountNumber')||'').trim().toUpperCase();
      const a=await env.DB.prepare("SELECT a.account_number,a.account_type,a.balance,a.status,a.branch_id,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=?").bind(number).first();
      if(!a) return response({error:'Account not found.'},404,request);
      if(user.staff_branch_id && a.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Account is outside your assigned branch.'},403,request);
      return response({customer:{name:a.display_name,username:a.username,accountNumber:a.account_number,accountType:a.account_type,balance:a.balance,status:a.status}},200,request);
    }
    if(method==='GET' && path==='/api/branch/loan-lookup') {
      const number=String(url.searchParams.get('loanNumber')||'').trim().toUpperCase();
      const loan=await env.DB.prepare("SELECT l.loan_number,l.principal_amount,l.outstanding_amount,l.monthly_payment,l.status,u.display_name,a.account_number,a.branch_id FROM demo_loans l JOIN users u ON u.id=l.user_id JOIN accounts a ON a.id=l.account_id WHERE l.loan_number=?").bind(number).first();
      if(!loan) return response({error:'Loan account not found.'},404,request);
      if(user.staff_branch_id && loan.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Loan account is outside your assigned branch.'},403,request);
      return response({loan:{loanNumber:loan.loan_number,borrower:loan.display_name,accountMasked:`••••${String(loan.account_number).slice(-4)}`,principal:loan.principal_amount,outstanding:loan.outstanding_amount,monthlyEmi:loan.monthly_payment,status:loan.status}},200,request);
    }
    if(method==='GET' && path==='/api/branch/card-lookup') {
      await ensureCardColumns(env);
      const last4=String(url.searchParams.get('last4')||'').replace(/\D/g,'').slice(-4), ownerAccount=String(url.searchParams.get('accountNumber')||'').trim().toUpperCase();
      if(!/^\d{4}$/.test(last4)||!ownerAccount) return response({error:'Enter card last 4 digits and cardholder account number.'},400,request);
      const cards=await env.DB.prepare("SELECT c.id,c.masked_number,c.credit_limit,c.outstanding,c.status,u.display_name,a.account_number,a.branch_id FROM virtual_cards c JOIN users u ON u.id=c.user_id JOIN accounts a ON a.user_id=u.id WHERE a.account_number=? AND (substr(replace(COALESCE(c.masked_number,''),' ',''),-4)=? OR substr(COALESCE(c.demo_number,''),-4)=?) ORDER BY c.created_at DESC LIMIT 2").bind(ownerAccount,last4,last4).all();
      if((cards.results||[]).length!==1) return response({error:cards.results?.length?'More than one card matched. Use the customer account and confirm with the cardholder.':'No matching card found for those details.'},cards.results?.length?409:404,request);
      const c=cards.results[0]; if(user.staff_branch_id && c.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Card account is outside your assigned branch.'},403,request); return response({card:{id:c.id,cardholder:c.display_name,accountMasked:`••••${ownerAccount.slice(-4)}`,maskedNumber:c.masked_number,creditLimit:c.credit_limit,outstanding:c.outstanding,status:c.status}},200,request);
    }
    if(method==='POST' && path==='/api/branch/account-operation') {
      const d=await body(request),number=String(d.accountNumber||'').trim().toUpperCase(),operation=String(d.operation||'').toLowerCase(),amount=Math.round(Number(d.amount)*100),reason=String(d.reason||'').trim().slice(0,240),idem=String(d.idempotencyKey||'');
      if(!['deposit','withdrawal'].includes(operation)||!Number.isSafeInteger(amount)||amount<100||reason.length<3||!/^[A-Za-z0-9._:-]{16,100}$/.test(idem)) return response({error:'Enter account, operation, amount, reason and payment reference.'},400,request);
      const prev=await env.DB.prepare('SELECT reference FROM branch_cash_operations WHERE idempotency_key=?').bind(idem).first(); if(prev)return response({ok:true,alreadyProcessed:true,reference:prev.reference},200,request);
      const a=await env.DB.prepare("SELECT a.*,u.display_name FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.status='active'").bind(number).first();
      if(!a)return response({error:'Active customer account not found.'},404,request);
      if(user.staff_branch_id && a.branch_id!==(user.staff_branch_id||'NB-HQ')) return response({error:'Account is outside your assigned branch.'},403,request);
      if(operation==='withdrawal'&&Number(a.balance)<amount)return response({error:'Insufficient customer balance.'},409,request);
      await ensureTreasury(env); const treasury=await env.DB.prepare('SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger').first();
      if(operation==='deposit'&&Number(treasury?.balance||0)<amount)return response({error:'Insufficient branch cash/Treasury funds for this deposit.'},409,request);
      const after=operation==='deposit'?Number(a.balance)+amount:Number(a.balance)-amount,reference=`NBC-${crypto.randomUUID().replace(/-/g,'').slice(0,16).toUpperCase()}`,group=uid(),opId=uid();
      await env.DB.batch([
        env.DB.prepare('UPDATE accounts SET balance=? WHERE id=? AND balance=? AND status=\'active\'').bind(after,a.id,Number(a.balance)),
        env.DB.prepare('INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)').bind(uid(),a.id,group,operation,amount,after,`Branch cash ${operation} · ${reason}`),
        env.DB.prepare('INSERT INTO branch_cash_operations(id,idempotency_key,account_id,actor_user_id,operation,amount,reason,reference) VALUES(?,?,?,?,?,?,?,?)').bind(opId,idem,a.id,user.id,operation,amount,reason,reference)
      ]);
      await postTreasury(env,user,operation==='deposit'?'branch_cash_deposit':'branch_cash_withdrawal',operation==='deposit'?-amount:amount,`Branch cash ${operation} · ${a.account_number} · ${reason}`,'branch_cash_operation',opId,group);
      await notify(env,a.user_id,`Branch ${operation} recorded`,`A branch cash ${operation} of NVR ${(amount/100).toFixed(2)} was recorded. Reference: ${reference}.`);
      await audit(env,user,`branch_cash_${operation}`,'account',a.id,{amount,reason,reference,branchId:user.staff_branch_id||'NB-HQ'});
      return response({ok:true,customer:a.display_name,accountNumber:a.account_number,balanceAfter:after,reference,message:`Cash ${operation} completed. New balance: NVR ${(after/100).toFixed(2)}.`},200,request);
    }
    if(method==='POST' && path==='/api/branch/card-payment') {
      await ensureCardColumns(env); await ensureCardTransactions(env); await ensureTreasury(env);
      const d=await body(request),cardId=String(d.cardId||''),methodType=String(d.paymentMethod||'cash'),amount=Math.round(Number(d.amount)*100),idem=String(d.idempotencyKey||'');
      if(!['cash','account'].includes(methodType)||!cardId||!Number.isSafeInteger(amount)||amount<100||!/^[A-Za-z0-9._:-]{16,100}$/.test(idem))return response({error:'Enter card, payment method, amount and reference.'},400,request);
      const prev=await env.DB.prepare('SELECT reference FROM branch_card_payment_records WHERE idempotency_key=?').bind(idem).first();if(prev)return response({ok:true,alreadyProcessed:true,reference:prev.reference},200,request);
      const card=await env.DB.prepare('SELECT * FROM virtual_cards WHERE id=?').bind(cardId).first();if(!card)return response({error:'Card not found.'},404,request);
      if(amount>Number(card.outstanding||0))return response({error:'Payment exceeds current card outstanding.'},409,request);
      let payer=null;
      if(methodType==='account'){payer=await env.DB.prepare("SELECT a.*,u.id AS owner_id FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.status='active'").bind(String(d.payerAccountNumber||'').trim().toUpperCase()).first();if(!payer)return response({error:'Active payer account not found.'},404,request);if(user.staff_branch_id && payer.branch_id!==(user.staff_branch_id||'NB-HQ'))return response({error:'Payer account is outside your assigned branch.'},403,request);if(Number(payer.balance)<amount)return response({error:'Insufficient payer account balance.'},409,request);}
      const group=uid(),reference=`NBCP-${crypto.randomUUID().replace(/-/g,'').slice(0,16).toUpperCase()}`,recordId=uid(),after=Number(card.outstanding)-amount;
      const ops=[env.DB.prepare('UPDATE virtual_cards SET outstanding=outstanding-? WHERE id=? AND outstanding>=?').bind(amount,card.id,amount)];
      if(payer){ops.push(env.DB.prepare('UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?').bind(amount,payer.id,amount));ops.push(env.DB.prepare('INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)').bind(uid(),payer.id,group,'card_bill_payment',amount,Number(payer.balance)-amount,`Branch card bill payment · ${card.masked_number}`));}
      ops.push(env.DB.prepare('INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)').bind(uid(),card.id,card.user_id,group,'bill_payment',amount,`Branch bill payment · ${methodType}`));
      ops.push(env.DB.prepare('INSERT INTO branch_card_payment_records(id,idempotency_key,card_id,card_owner_user_id,payer_user_id,payer_account_id,payment_method,amount,reference,actor_user_id) VALUES(?,?,?,?,?,?,?,?,?,?)').bind(recordId,idem,card.id,card.user_id,payer?.owner_id||null,payer?.id||null,methodType,amount,reference,user.id));
      await env.DB.batch(ops);
      await postTreasury(env,user,'card_bill_payment',amount,`Branch credit-card payment · ${card.masked_number} · ${methodType}`,'branch_card_payment',recordId,group);
      await notify(env,card.user_id,'Credit card payment received',`A branch payment of NVR ${(amount/100).toFixed(2)} was received. Remaining outstanding: NVR ${(after/100).toFixed(2)}.`);
      await audit(env,user,'branch_card_payment','virtual_card',card.id,{amount,methodType,reference,payerAccount:payer?.account_number||null});
      return response({ok:true,reference,outstanding:after,message:`Credit card payment received. Remaining outstanding: NVR ${(after/100).toFixed(2)}.`},200,request);
    }
    return response({error:'Branch Counter endpoint not found.'},404,request);
  }

  if (method === "POST" && path.startsWith("/api/admin/")) {
    if (!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    const d = await body(request);

    if(path === "/api/admin/manual-account-transaction") {
      await ensureApplicationTracking(env);
      if(!isSuperAdmin(user)) return response({error:"Super Admin permission required."},403,request);
      const accountNumber=String(d.accountNumber||"").trim(), operation=String(d.operation||"").toLowerCase(), amount=Math.round(Number(d.amount)*100), reason=String(d.reason||"").trim().slice(0,240);
      if(!/^NB[0-9A-Za-z]{6,20}$/i.test(accountNumber)||!['deposit','withdrawal'].includes(operation)||!Number.isSafeInteger(amount)||amount<100||amount>100000000000||reason.length<3) return response({error:"Enter a valid account number, operation, amount (minimum ₹1) and reason."},400,request);
      const account=await env.DB.prepare("SELECT a.*,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.account_number=? AND a.status='active'").bind(accountNumber).first();
      if(!account) return response({error:"No active account matches this account number."},404,request);
      if(operation==='withdrawal' && Number(account.balance)<amount) return response({error:"Insufficient account balance for this withdrawal."},409,request);
      await ensureTreasury(env);
      const treasury=await env.DB.prepare("SELECT COALESCE(SUM(amount),0) AS balance FROM treasury_ledger").first();
      if(operation==='deposit' && Number(treasury?.balance||0)<amount) return response({error:"Insufficient Treasury funds for this manual deposit."},409,request);
      const after=operation==='deposit'?Number(account.balance)+amount:Number(account.balance)-amount, group=uid(), operationId=uid();
      const change=await env.DB.prepare("UPDATE accounts SET balance=? WHERE id=? AND status='active' AND balance=?").bind(after,account.id,Number(account.balance)).run();
      if(!Number(change.meta?.changes||0)) return response({error:"Account balance changed during this operation. Refresh and retry."},409,request);
      await env.DB.batch([
        env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),account.id,group,operation,amount,after,`Super Admin manual ${operation} · ${reason}`),
        env.DB.prepare("INSERT INTO manual_account_operations(id,account_id,actor_user_id,operation,amount,reason,transaction_group) VALUES(?,?,?,?,?,?,?)").bind(operationId,account.id,user.id,operation,amount,reason,group)
      ]);
      await postTreasury(env,user,operation==='deposit'?'admin_manual_deposit':'admin_manual_withdrawal',operation==='deposit'?-amount:amount,`Manual ${operation} for ${account.account_number} · ${reason}`,'manual_account_operation',operationId,group);
      await notify(env,account.user_id,`Account ${operation} recorded`,`A Super Admin recorded a demo ${operation} of N₹${(amount/100).toFixed(2)}. Reference: ${operationId}.`);
      await audit(env,user,`manual_account_${operation}`,'account',account.id,{operationId,accountNumber,amount,reason,balanceAfter:after,transactionGroup:group});
      return response({ok:true,operationId,customer:account.display_name,accountNumber,balanceAfter:after/100,message:`Manual ${operation} completed. New balance: N₹${(after/100).toFixed(2)}.`},200,request);
    }

    const cardControlReview=path.match(/^\/api\/admin\/card-control-requests\/([^/]+)\/review$/);
    if(cardControlReview){
      const status=String(d.status||''),note=String(d.note||'').trim().slice(0,250);
      if(!['approved','rejected'].includes(status)) return response({error:'Choose approve or reject.'},400,request);
      const r=await env.DB.prepare("SELECT * FROM card_control_requests WHERE id=? AND status='pending'").bind(cardControlReview[1]).first();
      if(!r) return response({error:'Pending card control request not found.'},404,request);
      const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(r.card_id,r.user_id).first();
      if(!card) return response({error:'Card not found.'},404,request);
      if(status==='approved'){
        const next=r.action==='unblock'?'active':'blocked';
        const expected=r.action==='unblock'?'blocked':'active';
        const changed=await env.DB.prepare("UPDATE virtual_cards SET status=? WHERE id=? AND user_id=? AND status=?").bind(next,card.id,r.user_id,expected).run();
        if(!Number(changed.meta?.changes||0)) return response({error:`Card status changed since request; expected ${expected}. Refresh and review again.`},409,request);
      }
      await env.DB.prepare("UPDATE card_control_requests SET status=?,admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(status,note,user.id,r.id).run();
      await notify(env,r.user_id,`Card ${r.action} request ${status}`,status==='approved'?`Your demo card is now ${r.action==='unblock'?'active':'blocked'}.`: `Your card ${r.action} request was rejected. ${note}`);
      await audit(env,user,`card_${r.action}_${status}`,'virtual_card',r.card_id,{requestId:r.id,note});
      return response({ok:true,message:`Card ${r.action} request ${status}.`},200,request);
    }

    const closureArchive = path.match(/^\/api\/admin\/closure-requests\/([^/]+)\/archive$/);
    if (closureArchive) {
      await ensureColumn(env,"product_closure_requests","deleted_at","TEXT");
      const req=await env.DB.prepare("SELECT * FROM product_closure_requests WHERE id=? AND deleted_at IS NULL").bind(closureArchive[1]).first();
      if(!req) return response({error:"Closure request is already hidden or was not found."},404,request);
      if(req.product_type==='loan' && req.status==='pending') return response({error:"This loan foreclosure has already deducted funds. Review it first so the payment is approved or safely reversed before hiding the request."},409,request);
      if(req.product_type==='card' && req.status==='pending') {
        const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(req.product_id,req.user_id).first();
        if(!card) return response({error:"Card record not found; cannot safely archive this request."},404,request);
        if(Number(card.outstanding)>0) return response({error:"This card has outstanding dues. Resolve the card before archiving its pending closure request."},409,request);
        if(card.status==='closure_pending') await env.DB.prepare("UPDATE virtual_cards SET status='active' WHERE id=? AND user_id=? AND status='closure_pending'").bind(card.id,req.user_id).run();
        else if(!['active','blocked'].includes(card.status)) return response({error:`Cannot archive a pending closure request while the card status is ${card.status}.`},409,request);
      }
      const changed=await env.DB.prepare("UPDATE product_closure_requests SET deleted_at=datetime('now') WHERE id=? AND deleted_at IS NULL").bind(req.id).run();
      if(!Number(changed.meta?.changes||0)) return response({error:"Request changed while archiving. Refresh the queue."},409,request);
      await audit(env,user,"product_closure_request_soft_deleted","product_closure_request",req.id,{productType:req.product_type,productId:req.product_id,status:req.status,reason:String(d.note||"Hidden from active review list").slice(0,250)});
      return response({ok:true,message:"Closure request hidden from the active review list. Request and financial history are preserved."},200,request);
    }

    const closureReview = path.match(/^\/api\/admin\/closure-requests\/([^/]+)\/review$/);
    if (closureReview) {
      const status=String(d.status||""), note=String(d.note||"").trim().slice(0,250);
      if(!["approved","rejected"].includes(status)) return response({error:"Choose approve or reject."},400,request);
      const r=await env.DB.prepare("SELECT * FROM product_closure_requests WHERE id=? AND status='pending' AND deleted_at IS NULL").bind(closureReview[1]).first();
      if(!r) return response({error:"Pending closure request not found."},404,request);
      if(r.product_type==='loan') {
        const loan=await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND user_id=? AND status='closure_pending'").bind(r.product_id,r.user_id).first();
        if(!loan) return response({error:"Loan is no longer awaiting closure."},409,request);
        if(status==='approved') {
          const changed=await env.DB.prepare("UPDATE demo_loans SET outstanding_amount=0,remaining_months=0,status='closed',updated_at=datetime('now') WHERE id=? AND user_id=? AND status='closure_pending'").bind(loan.id,r.user_id).run();
          if(!Number(changed.meta?.changes||0)) return response({error:"Loan closure could not be approved because its status changed. Refresh and review again."},409,request);
          await env.DB.prepare("UPDATE loan_applications SET status='closed',updated_at=datetime('now') WHERE id=? AND user_id=?").bind(loan.application_id,r.user_id).run();
        } else {
          const acct=await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=?").bind(loan.account_id,r.user_id).first();
          if(!acct) return response({error:"Linked demo account not found; cannot safely reverse payment."},409,request);
          const group=uid(),amount=Number(r.amount_paid),after=Number(acct.balance)+amount;
          await env.DB.batch([
            env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND user_id=?").bind(amount,acct.id,r.user_id),
            env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),acct.id,group,"loan_foreclosure_reversal",amount,after,"Reversal of rejected demo loan closure request"),
            env.DB.prepare("UPDATE demo_loans SET status='active',updated_at=datetime('now') WHERE id=? AND status='closure_pending'").bind(loan.id)
          ]);
          await postTreasury(env,user,"foreclosure_reversal",-amount,`Rejected foreclosure reversed · ${loan.id}`,"product_closure_request",r.id,group);
        }
      } else {
        const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(r.product_id,r.user_id).first();
        if(!card) return response({error:"Card record not found. Refresh the queue and inspect the customer history."},404,request);
        if(Number(card.outstanding||0)!==0) return response({error:`Card closure requires zero outstanding. Current outstanding is N₹${(Number(card.outstanding||0)/100).toFixed(2)}.`},409,request);
        if(status==='approved') {
          if(card.status!=='closed') {
            if(!['closure_pending','active','blocked'].includes(card.status)) return response({error:`Card cannot be closed from its current status (${card.status}). Refresh and inspect the card.`},409,request);
            const changed=await env.DB.prepare("UPDATE virtual_cards SET status='closed' WHERE id=? AND user_id=? AND status=? AND outstanding=0").bind(card.id,r.user_id,card.status).run();
            if(!Number(changed.meta?.changes||0)) return response({error:"Card status changed during approval. Refresh and review again."},409,request);
            await env.DB.prepare("UPDATE card_applications SET status='closed',deleted_at=COALESCE(deleted_at,datetime('now')),updated_at=datetime('now') WHERE id=? AND user_id=?").bind(card.id,r.user_id).run();
          }
        } else {
          // A pending closure request is not the card itself. If an older build
          // marked the card closure_pending, restore it to active; otherwise keep
          // the current usable/blocked state instead of failing on a status mismatch.
          if(card.status==='closure_pending') {
            const changed=await env.DB.prepare("UPDATE virtual_cards SET status='active' WHERE id=? AND user_id=? AND status='closure_pending' AND outstanding=0").bind(card.id,r.user_id).run();
            if(!Number(changed.meta?.changes||0)) return response({error:"Card status changed during rejection. Refresh and review again."},409,request);
          } else if(!['active','blocked'].includes(card.status)) {
            return response({error:`Card closure cannot be rejected because the card is ${card.status}. Inspect the card before retrying.`},409,request);
          }
        }
      }
      const requestChanged=await env.DB.prepare("UPDATE product_closure_requests SET status=?,admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending' AND deleted_at IS NULL").bind(status,note,user.id,r.id).run();
      if(!Number(requestChanged.meta?.changes||0)) return response({error:"Closure request was already reviewed or hidden. Refresh the queue."},409,request);
      await notify(env,r.user_id,`${r.product_type==='loan'?'Loan':'Card'} closure ${status}`,status==='approved'?"Your demo product has been closed and removed from active products.":`Your closure request was rejected. ${note}`);
      await audit(env,user,`${r.product_type}_closure_${status}`,r.product_type,r.product_id,{requestId:r.id,note});
      return response({ok:true,message:`Closure request ${status}.`},200,request);
    }
    const offerArchiveMatch = path.match(/^\/api\/admin\/offers\/([^/]+)\/archive$/);
    if (offerArchiveMatch && method === "POST") {
      await ensureColumn(env, "offers", "deleted_at", "TEXT");
      const offer = await env.DB.prepare("SELECT id,title FROM offers WHERE id=? AND deleted_at IS NULL").bind(offerArchiveMatch[1]).first();
      if (!offer) return response({error:"Offer was already removed or was not found."},404,request);
      const changed = await env.DB.prepare("UPDATE offers SET deleted_at=datetime('now'),active=0,updated_at=datetime('now') WHERE id=? AND deleted_at IS NULL").bind(offer.id).run();
      if (!Number(changed.meta?.changes||0)) return response({error:"Offer changed while removing. Refresh and retry."},409,request);
      await audit(env,user,"offer_archived","offer",offer.id,{title:offer.title,note:String(d.note||"Removed by Super Admin").slice(0,250)});
      return response({ok:true,message:"Offer removed from customer portals. Record and audit history are preserved."},200,request);
    }

    const assignOfferMatch = path.match(/^\/api\/admin\/offers\/([^/]+)\/assign$/);
    if (assignOfferMatch) {
      const targetUser = String(d.userId || "").trim();
      const offer = await env.DB.prepare("SELECT id,title FROM offers WHERE id=?").bind(assignOfferMatch[1]).first();
      const customer = await env.DB.prepare("SELECT id FROM users WHERE id=? AND role='customer'").bind(targetUser).first();
      if (!offer || !customer) return response({error:"Offer or customer not found."},404,request);
      if (d.assigned === false) {
        await env.DB.prepare("DELETE FROM offer_assignments WHERE offer_id=? AND user_id=?").bind(offer.id,customer.id).run();
      } else {
        await env.DB.prepare("INSERT OR IGNORE INTO offer_assignments(offer_id,user_id,assigned_by) VALUES(?,?,?)").bind(offer.id,customer.id,user.id).run();
      }
      await audit(env,user,d.assigned===false?"offer_unassigned":"offer_assigned","offer",offer.id,{userId:customer.id,title:offer.title});
      return response({ok:true},200,request);
    }

    const foreclosureMatch = path.match(/^\/api\/admin\/loans\/([^/]+)\/foreclose$/);
    if (foreclosureMatch) {
      const loan = await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND status='active'").bind(foreclosureMatch[1]).first();
      if (!loan) return response({ error: "Active demo loan not found." }, 404, request);
      const account = await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(loan.account_id,loan.user_id).first();
      if (!account) return response({ error: "Customer's linked account is not active." }, 400, request);
      const amount = Number(loan.outstanding_amount);
      if (!Number.isSafeInteger(amount) || amount <= 0) return response({ error: "Loan has no outstanding amount to foreclose." }, 400, request);
      if (Number(account.balance) < amount) return response({ error: `Insufficient demo balance. Full one-time foreclosure requires N₹${(amount/100).toFixed(2)}.` }, 400, request);
      const group = uid(), ledgerId = uid(), before = Number(account.balance), after = before - amount;
      const results = await env.DB.batch([
        env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND user_id=? AND status='active' AND balance>=?").bind(amount,account.id,loan.user_id,amount),
        env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) SELECT ?,?,?,?,?,?,? WHERE EXISTS(SELECT 1 FROM accounts WHERE id=? AND balance=?)").bind(ledgerId,account.id,group,"loan_foreclosure",amount,after,`One-time full loan foreclosure · ${loan.id}`,account.id,after),
        env.DB.prepare("UPDATE demo_loans SET outstanding_amount=0,remaining_months=0,status='closed',updated_at=datetime('now') WHERE id=? AND status='active' AND outstanding_amount=? AND EXISTS(SELECT 1 FROM ledger WHERE id=? AND transaction_group=?)").bind(loan.id,amount,ledgerId,group),
        env.DB.prepare("UPDATE loan_applications SET status='closed',updated_at=datetime('now') WHERE id=? AND user_id=? AND EXISTS(SELECT 1 FROM demo_loans WHERE id=? AND status='closed')").bind(loan.application_id,loan.user_id,loan.id)
      ]);
      const changed=Number(results?.[0]?.meta?.changes||0), ledgerChanged=Number(results?.[1]?.meta?.changes||0), closed=Number(results?.[2]?.meta?.changes||0);
      if(!changed || !ledgerChanged || !closed) return response({ error:"Foreclosure could not be completed safely. Refresh the record and retry." },409,request);
      await postTreasury(env,user,"admin_foreclosure",amount,`Admin-recorded loan foreclosure · ${loan.id}`,"demo_loan",loan.id,group);
      await notify(env,loan.user_id,"Demo loan foreclosed",`Your demo loan ${loan.id} was fully paid through a one-time foreclosure payment of N₹${(amount/100).toFixed(2)}. Remaining balance is N₹0.00.`);
      await audit(env,user,"demo_loan_foreclosed","demo_loan",loan.id,{amount,accountId:account.id,transactionGroup:group,oneTimePayment:true});
      return response({ok:true,message:`Loan foreclosed with one-time demo payment of N₹${(amount/100).toFixed(2)}.`,paidAmount:amount/100,remainingOutstanding:0},200,request);
    }

    const loanMatch = path.match(/^\/api\/admin\/loans\/([^/]+)\/review$/);
    if (loanMatch) {
      await ensureApplicationTracking(env);
      const status=String(d.status||""), allowed=["need_documents","verified","approved","rejected"];
      if (!allowed.includes(status)) return response({error:"Invalid review status."},400,request);
      const amount = d.sanctionedAmount == null ? null : Math.round(Number(d.sanctionedAmount)*100);
      const loan=await env.DB.prepare("SELECT * FROM loan_applications WHERE id=?").bind(loanMatch[1]).first();
      if(!loan) return response({error:"Application not found."},404,request);
      if(status==="approved" && (!Number.isSafeInteger(amount)||amount<100||amount>loan.requested_amount)) return response({error:"Approved amount must be positive and not exceed requested amount."},400,request);
      const processingFee=status==="approved"?Math.round(amount*0.05):0, fileCharge=status==="approved"?110000:0, netDisbursement=status==="approved"?amount-processingFee-fileCharge:0;
      if(status==="approved" && netDisbursement<=0) return response({error:"Sanction amount must be greater than the 5% processing fee plus ₹1,100 file charge."},400,request);
      await ensureApplicationTracking(env);
      await env.DB.prepare("UPDATE loan_applications SET status=?,sanctioned_amount=?,processing_fee=?,file_charge=?,net_disbursement=?,admin_note=?,deleted_at=CASE WHEN ? IN ('approved','rejected') THEN COALESCE(deleted_at,datetime('now')) ELSE NULL END,updated_at=datetime('now') WHERE id=?").bind(status,amount,processingFee,fileCharge,netDisbursement,String(d.note||""),status,loan.id).run();
      await notify(env,loan.user_id,"Loan application update",status==="approved"?`Your application ${loan.application_number||loan.id} is approved. Sanction: N₹${(amount/100).toFixed(2)}; processing fee (5%): N₹${(processingFee/100).toFixed(2)}; file charge: N₹${(fileCharge/100).toFixed(2)}; net disbursement: N₹${(netDisbursement/100).toFixed(2)}. Review and accept the offer to proceed.`:`Your demo loan application status is now: ${status}. ${String(d.note||"")}`);
      await audit(env,user,"loan_review","loan_application",loan.id,{applicationNumber:loan.application_number,status,amount,processingFee,fileCharge,netDisbursement,note:d.note||""});
      return response({ok:true,applicationNumber:loan.application_number,processingFee:processingFee/100,fileCharge:fileCharge/100,netDisbursement:netDisbursement/100},200,request);
    }
    const cardMatch = path.match(/^\/api\/admin\/cards\/([^/]+)\/review$/);
    if (cardMatch) {
      await ensureCardColumns(env);
      const status=String(d.status||""), allowed=["need_documents","verified","approved","rejected"];
      if(!allowed.includes(status)) return response({error:"Invalid review status."},400,request);
      const amount=d.sanctionedLimit==null?null:Math.round(Number(d.sanctionedLimit)*100);
      const card=await env.DB.prepare("SELECT * FROM card_applications WHERE id=?").bind(cardMatch[1]).first();
      if(!card) return response({error:"Application not found."},404,request);
      if(status==="approved"&&(!Number.isSafeInteger(amount)||amount<100||amount>20000000)) return response({error:"Approved limit must be between N₹1 and N₹200,000."},400,request);
      await env.DB.prepare("UPDATE card_applications SET status=?,sanctioned_limit=?,admin_note=?,deleted_at=CASE WHEN ? IN ('approved','rejected') THEN COALESCE(deleted_at,datetime('now')) ELSE NULL END,updated_at=datetime('now') WHERE id=?").bind(status,amount,String(d.note||""),status,card.id).run();
      if(status==="approved") {
        const finalLimit = Number(amount);
        const suffix = String(card.id).replace(/[^a-z0-9]/gi,"").slice(-4).toUpperCase().padStart(4,"0");
        const demoHash = await digest(card.id); const demoNumber = "9000" + demoHash.slice(0,12).replace(/[^0-9]/g,"7").padEnd(12,"7") + suffix;
        await env.DB.prepare("INSERT INTO virtual_cards(id,user_id,masked_number,credit_limit,outstanding,status,activation_pending,demo_number) VALUES(?,?,?,?,0,'active',1,?) ON CONFLICT(id) DO UPDATE SET credit_limit=excluded.credit_limit, status='active', activation_pending=1, demo_number=excluded.demo_number").bind(card.id,card.user_id,`•••• •••• •••• ${suffix}`,finalLimit,demoNumber).run();
      }
      await notify(env,card.user_id,"Virtual card application update",`Your demo card application status is now: ${status}. ${String(d.note||"")}`);
      await audit(env,user,"card_review","card_application",card.id,{status,amount,note:d.note||""});
      return response({ok:true},200,request);
    }
  }
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS card_control_requests (
    id TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),card_id TEXT NOT NULL REFERENCES virtual_cards(id),
    action TEXT NOT NULL CHECK(action IN ('block','unblock')),status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    note TEXT NOT NULL DEFAULT '',admin_note TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT (datetime('now')),
    reviewed_at TEXT,reviewed_by TEXT REFERENCES users(id)
  )`).run();
  const cardControlRequest = path.match(/^\/api\/cards\/([^/]+)\/control-request$/);
  if(method==='POST' && cardControlRequest){
    const d=await body(request), action=String(d.action||'').toLowerCase();
    if(!['block','unblock'].includes(action)) return response({error:'Choose block or unblock.'},400,request);
    const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status IN ('active','blocked') AND activation_pending=0").bind(cardControlRequest[1],user.id).first();
    if(!card) return response({error:'Eligible demo card not found.'},404,request);
    if(action==='unblock' && card.status!=='blocked') return response({error:'Only a blocked card can request unblocking.'},409,request);
    if(action==='block' && card.status!=='active') return response({error:'Only an active card can be blocked.'},409,request);
    const duplicate=await env.DB.prepare("SELECT id FROM card_control_requests WHERE card_id=? AND action=? AND status='pending'").bind(card.id,action).first();
    if(duplicate) return response({error:`A ${action} request is already pending for this card.`},409,request);
    const id=uid();
    await env.DB.prepare("INSERT INTO card_control_requests(id,user_id,card_id,action,note) VALUES(?,?,?,?,?)").bind(id,user.id,card.id,action,String(d.note||'Customer requested card control').slice(0,240)).run();
    await notify(env,user.id,`Card ${action} request submitted`,`Your demo card ${action} request is awaiting admin review.`);
    await audit(env,user,`card_${action}_requested`,'virtual_card',card.id,{requestId:id});
    return response({ok:true,requestId:id,message:`Card ${action} request submitted for admin approval.`},201,request);
  }
  if(method==='GET' && path==='/api/card-control-requests'){
    const rows=await env.DB.prepare("SELECT r.*,c.masked_number FROM card_control_requests r JOIN virtual_cards c ON c.id=r.card_id WHERE r.user_id=? ORDER BY r.created_at DESC LIMIT 100").bind(user.id).all();
    return response({requests:rows.results||[]},200,request);
  }
  if(method==='GET' && path==='/api/admin/card-control-requests'){
    if(!hasStaffPermission(user, method, path)) return response({error:'Insufficient role permission.'},403,request);
    const rows=await env.DB.prepare(`SELECT r.*,u.display_name,u.username,c.masked_number,c.outstanding FROM card_control_requests r JOIN users u ON u.id=r.user_id JOIN virtual_cards c ON c.id=r.card_id ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 300`).all();
    return response({requests:rows.results||[]},200,request);
  }

  const cardActivateMatch = path.match(/^\/api\/cards\/([^/]+)\/activate$/);
  if (method === "POST" && cardActivateMatch) {
    await ensureCardColumns(env);
    const card = await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(cardActivateMatch[1],user.id).first();
    if (!card) return response({error:"Virtual card not found."},404,request);
    if (card.status === "blocked") return response({error:"Blocked card must be unblocked by an admin."},400,request);
    const joiningFee=50000;
    if(Number(card.credit_limit)<joiningFee) return response({error:"Approved card limit must be at least N₹500 to cover the demo joining fee."},400,request);
    await ensureCardTransactions(env);
    const feeGroup=uid();
    const activated=await env.DB.prepare("UPDATE virtual_cards SET status='active',activation_pending=0,outstanding=outstanding+? WHERE id=? AND user_id=? AND status='active' AND activation_pending=1 AND credit_limit-outstanding>=?").bind(joiningFee,card.id,user.id,joiningFee).run();
    if(!Number(activated.meta?.changes||0)) return response({error:"Card could not be activated safely. Refresh and check its status/available limit."},409,request);
    await env.DB.prepare("INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),card.id,user.id,feeGroup,"joining_fee",joiningFee,"Nova Rewards Card joining fee (N₹500)").run();
    await postTreasury(env,user,"card_joining_fee",joiningFee,"N₹500 demo card joining fee","virtual_card",card.id,feeGroup);
    await audit(env,user,"demo_card_activated","virtual_card",card.id,{joiningFee});
    return response({ok:true,message:"Demo card activated. N₹500 joining fee added to card outstanding.",joiningFee:500},200,request);
  }
  const cardBlockMatch = path.match(/^\/api\/cards\/([^/]+)\/block$/);
  if (method === "POST" && cardBlockMatch) {
    const card = await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(cardBlockMatch[1],user.id).first();
    if (!card) return response({error:"Virtual card not found."},404,request);
    await env.DB.prepare("UPDATE virtual_cards SET status='blocked' WHERE id=? AND user_id=?").bind(card.id,user.id).run();
    await audit(env,user,"demo_card_blocked","virtual_card",card.id);
    return response({ok:true,message:"Demo card blocked."},200,request);
  }
  const cardPurchaseMatch = path.match(/^\/api\/cards\/([^/]+)\/purchase$/);
  if (method === "POST" && cardPurchaseMatch) {
    const d=await body(request), amount=Math.round(Number(d.amount)*100), merchant=String(d.merchant||"Demo Store").trim().slice(0,80);
    if(!Number.isSafeInteger(amount)||amount<100||amount>20000000) return response({error:"Enter a purchase amount between N₹1 and N₹200,000."},400,request);
    const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status='active'").bind(cardPurchaseMatch[1],user.id).first();
    if(!card) return response({error:"Card is not active."},400,request);
    if(Number(card.credit_limit)-Number(card.outstanding)<amount) return response({error:"Insufficient available demo credit."},400,request);
    const result=await env.DB.prepare("UPDATE virtual_cards SET outstanding=outstanding+? WHERE id=? AND user_id=? AND status='active' AND credit_limit-outstanding>=?").bind(amount,card.id,user.id,amount).run();
    if(!result.success || result.meta?.changes===0) return response({error:"Purchase could not be completed; refresh and try again."},409,request);
    await ensureCardTransactions(env); const txGroup=uid();
    await env.DB.prepare("INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),card.id,user.id,txGroup,"purchase",amount,`Demo purchase at ${merchant}`).run();
    await postTreasury(env,user,"card_purchase",0,`Demo card purchase N₹${(amount/100).toFixed(2)} at ${merchant}`,"virtual_card",card.id,txGroup);
    await audit(env,user,"demo_card_purchase","virtual_card",card.id,{amount,merchant});
    await notify(env,user.id,"Demo card purchase",`N₹${(amount/100).toFixed(2)} demo purchase at ${merchant}.`);
    return response({ok:true,message:"Demo purchase recorded.",outstanding:Number(card.outstanding)+amount,availableCredit:Number(card.credit_limit)-Number(card.outstanding)-amount},200,request);
  }
  const cardRepayMatch = path.match(/^\/api\/cards\/([^/]+)\/repay$/);
  if (method === "POST" && cardRepayMatch) {
    const d=await body(request), amount=Math.round(Number(d.amount)*100);
    if(!Number.isSafeInteger(amount)||amount<100) return response({error:"Enter a repayment amount of at least N₹1."},400,request);
    const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(cardRepayMatch[1],user.id).first();
    if(!card||Number(card.outstanding)<=0) return response({error:"No card outstanding found."},404,request);
    if(amount>Number(card.outstanding)) return response({error:"Repayment cannot exceed card outstanding."},400,request);
    const account=await env.DB.prepare("SELECT * FROM accounts WHERE user_id=? AND status='active' ORDER BY opened_at LIMIT 1").bind(user.id).first();
    if(!account||Number(account.balance)<amount) return response({error:"Insufficient demo account balance for repayment."},400,request);
    const group=uid();
    const results=await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND balance>=?").bind(amount,account.id,amount),
      env.DB.prepare("UPDATE virtual_cards SET outstanding=outstanding-? WHERE id=? AND outstanding>=?").bind(amount,card.id,amount),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),account.id,group,"card_repayment",amount,Number(account.balance)-amount,"Demo credit card repayment")
    ]);
    await ensureCardTransactions(env);
    await env.DB.prepare("INSERT INTO card_transactions(id,card_id,user_id,transaction_group,type,amount,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),card.id,user.id,group,"repayment",amount,"Demo credit card repayment").run();
    await postTreasury(env,user,"card_repayment",amount,`Demo credit card repayment · ${card.id}`,"virtual_card",card.id,group);
    await audit(env,user,"demo_card_repayment","virtual_card",card.id,{amount});
    return response({ok:true,message:"Demo card repayment recorded."},200,request);
  }

  if (method === "GET" && path === "/api/notifications") {
    const rows=await env.DB.prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return response({notifications:rows.results||[]},200,request);
  }
  if (method === "GET" && path === "/api/admin/audit") {
    if(!hasStaffPermission(user, method, path)) return response({error:"Insufficient role permission."},403,request);
    const rows=await env.DB.prepare("SELECT * FROM audit_events ORDER BY created_at DESC LIMIT 300").all();
    return response({events:rows.results||[]},200,request);
  }
  return response({error:"API route not found."},404,request);
}

export default {
  async fetch(request, env) {
    try { return await route(request, env); }
    catch (e) {
      // Do not expose database details or stack traces to clients.
      return new Response(JSON.stringify({ error: "Unexpected server error. Check Worker logs." }), { status: 500, headers: { "content-type": "application/json", "cache-control": "no-store", "x-content-type-options":"nosniff", "referrer-policy":"no-referrer", "x-frame-options":"DENY", ...corsHeaders(request) } });
    }
  }
};
