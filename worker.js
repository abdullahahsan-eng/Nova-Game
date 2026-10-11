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
  return { "access-control-allow-origin": origin, "vary": "Origin", "access-control-allow-headers": "content-type,authorization", "access-control-allow-methods": "GET,POST,PATCH,OPTIONS" };
}
async function body(request) {
  try { return await request.json(); } catch { return {}; }
}
async function auth(request, env) {
  const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
  if (!token) return null;
  const tokenHash = await digest(token);
  const row = await env.DB.prepare(
    `SELECT u.id,u.username,u.display_name,u.email,u.role,u.status,s.expires_at
     FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`
  ).bind(tokenHash).first();
  if (!row || new Date(row.expires_at).getTime() < Date.now() || row.status !== "active") return null;
  return row;
}
function response(data, status, request) {
  return new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...corsHeaders(request) } });
}
async function audit(env, actor, action, targetType, targetId, details = {}) {
  await env.DB.prepare("INSERT INTO audit_events(id,actor_user_id,action,target_type,target_id,details) VALUES(?,?,?,?,?,?)")
    .bind(uid(), actor?.id || null, action, targetType, targetId || null, JSON.stringify(details)).run();
}
async function notify(env, userId, title, message) {
  await env.DB.prepare("INSERT INTO notifications(id,user_id,title,message) VALUES(?,?,?,?)").bind(uid(), userId, title, message).run();
}
async function route(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (method === "GET" && path === "/api/health") return response({ ok: true, app: "NovaBank", mode: "fictional-simulator" }, 200, request);

  if (method === "POST" && path === "/api/setup-admin") {
    const data = await body(request);
    if (!env.ADMIN_SETUP_KEY || data.setupKey !== env.ADMIN_SETUP_KEY) return response({ error: "Invalid setup key" }, 403, request);
    const exists = await env.DB.prepare("SELECT id FROM users WHERE role='admin' LIMIT 1").first();
    if (exists) return response({ error: "Admin already exists; disable setup endpoint now." }, 409, request);
    if (!data.username || !data.password || String(data.password).length < 12 || !data.email || !data.displayName) return response({ error: "Provide username, displayName, email and a password of at least 12 characters." }, 400, request);
    const salt = uid(), id = uid(), hash = await passwordHash(data.password, salt);
    await env.DB.prepare("INSERT INTO users(id,username,display_name,email,password_hash,password_salt,role) VALUES(?,?,?,?,?,?,'admin')")
      .bind(id, data.username.toLowerCase(), data.displayName, data.email.toLowerCase(), hash, salt).run();
    await audit(env, { id }, "admin_bootstrap", "user", id);
    return response({ ok: true, message: "Admin created. Disable setup endpoint/secret after confirming login." }, 201, request);
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
        env.DB.prepare("INSERT INTO accounts(id,user_id,account_number,balance) VALUES(?,?,?,0)").bind(accountId, userId, accountNumber)
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
    const user = await env.DB.prepare("SELECT * FROM users WHERE username=? OR email=?").bind(login, login).first();
    if (!user || user.status !== "active" || (await passwordHash(String(d.password || ""), user.password_salt)) !== user.password_hash)
      return response({ error: "Invalid login or password." }, 401, request);
    const token = b64(crypto.getRandomValues(new Uint8Array(32)));
    const expires = new Date(Date.now() + 1000 * 60 * 60 * 24).toISOString();
    await env.DB.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)").bind(await digest(token), user.id, expires).run();
    await audit(env, user, "login", "user", user.id);
    return response({ token, user: { id:user.id, username:user.username, displayName:user.display_name, email:user.email, role:user.role } }, 200, request);
  }

  const user = await auth(request, env);
  if (method === "POST" && path === "/api/logout") {
    const token = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "");
    if (token) await env.DB.prepare("DELETE FROM sessions WHERE token_hash=?").bind(await digest(token)).run();
    return response({ ok: true }, 200, request);
  }
  if (!user) return response({ error: "Please log in." }, 401, request);
  if (method === "GET" && path === "/api/me") return response({ user }, 200, request);

  // Offers are fictional simulator content, managed by admins in the dashboard.
  if (path === "/api/offers" && method === "GET") {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offers (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, benefit TEXT NOT NULL DEFAULT '', cta_label TEXT NOT NULL DEFAULT 'Explore offer',
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), valid_until TEXT NOT NULL DEFAULT '',
      created_by TEXT REFERENCES users(id), created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    const count = await env.DB.prepare("SELECT COUNT(*) AS n FROM offers").first();
    if (!count || Number(count.n) === 0) {
      const seeds = [
        [uid(), "Nova Rewards Card", "Credit Card", "Explore a fictional virtual card with reward points for simulated purchases.", "Up to 5% demo rewards", "View card options", 1, ""],
        [uid(), "Nova Flexi Loan", "Personal Loan", "Try a sample loan application and see a simulated eligibility estimate. Approval is not guaranteed.", "0% demo interest", "Apply for demo loan", 1, ""],
        [uid(), "Smart Shopper Bonus", "Shopping", "Earn fictional reward points by completing learning challenges in the simulator.", "500 demo points", "Explore rewards", 1, ""]
      ];
      await env.DB.batch(seeds.map(x => env.DB.prepare("INSERT INTO offers(id,title,category,description,benefit,cta_label,active,valid_until) VALUES(?,?,?,?,?,?,?,?)").bind(...x)));
    }
    const rows = user.role === "admin"
      ? await env.DB.prepare("SELECT * FROM offers ORDER BY created_at DESC").all()
      : await env.DB.prepare("SELECT * FROM offers WHERE active=1 AND (valid_until='' OR valid_until>=date('now')) ORDER BY created_at DESC").all();
    return response({ offers: rows.results || [] }, 200, request);
  }

  if (path === "/api/admin/offers" && method === "POST") {
    if (user.role !== "admin") return response({ error: "Admin permission required." }, 403, request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS offers (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, category TEXT NOT NULL,
      description TEXT NOT NULL, benefit TEXT NOT NULL DEFAULT '', cta_label TEXT NOT NULL DEFAULT 'Explore offer',
      active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)), valid_until TEXT NOT NULL DEFAULT '',
      created_by TEXT REFERENCES users(id), created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
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
    if (user.role !== "admin") return response({ error: "Admin permission required." }, 403, request);
    const d = await body(request), current = await env.DB.prepare("SELECT * FROM offers WHERE id=?").bind(offerMatch[1]).first();
    if (!current) return response({ error: "Offer not found." }, 404, request);
    const active = d.active === undefined ? current.active : (d.active ? 1 : 0);
    await env.DB.prepare("UPDATE offers SET active=?, updated_at=datetime('now') WHERE id=?").bind(active, current.id).run();
    await audit(env, user, active ? "offer_activated" : "offer_deactivated", "offer", current.id, { title: current.title });
    return response({ ok: true, active }, 200, request);
  }

  if (method === "GET" && path === "/api/accounts") {
    const rows = user.role === "admin"
      ? await env.DB.prepare("SELECT a.*,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id ORDER BY a.opened_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM accounts WHERE user_id=?").bind(user.id).all();
    return response({ accounts: rows.results || [] }, 200, request);
  }
  if (method === "GET" && path === "/api/transactions") {
    const accountId = url.searchParams.get("accountId");
    let q;

    // Customers may load recent activity before selecting an account.
    // In that case, return transactions for all accounts they own.
    if (user.role === "admin" && !accountId) {
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id ORDER BY l.created_at DESC LIMIT 500"
      );
    } else if (!accountId && user.role !== "admin") {
      q = env.DB.prepare(
        "SELECT l.*,a.account_number FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.user_id=? ORDER BY l.created_at DESC LIMIT 200"
      ).bind(user.id);
    } else if (user.role === "admin") {
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
  if (method === "POST" && path === "/api/transfer") {
    const d = await body(request), amount = Math.round(Number(d.amount) * 100);
    if (!Number.isSafeInteger(amount) || amount < 100 || amount > 100000000) return response({ error: "Transfer amount must be between N₹1 and N₹1,000,000." }, 400, request);
    const source = await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(d.fromAccountId, user.id).first();
    const dest = await env.DB.prepare("SELECT * FROM accounts WHERE account_number=? AND status='active'").bind(String(d.toAccountNumber || "").trim()).first();
    if (!source || !dest || source.id === dest.id) return response({ error: "Check source and recipient account." }, 400, request);
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
    await audit(env, user, "demo_transfer", "transaction", group, { amount, from: source.id, to: dest.id });
    await notify(env, dest.user_id, "Money received", `N₹${(amount/100).toFixed(2)} demo transfer received.`);
    return response({ ok: true, message: "Demo transfer submitted.", transactionId: group }, 200, request);
  }
  if (method === "POST" && path === "/api/loans") {
    const d = await body(request), amount = Math.round(Number(d.requestedAmount)*100), tenure = Number(d.tenureMonths);
    if (!Number.isSafeInteger(amount) || amount < 10000 || amount > 500000000 || !Number.isInteger(tenure) || tenure < 1 || tenure > 120 || String(d.purpose||"").trim().length < 3)
      return response({ error: "Enter a valid demo loan amount, tenure (1–120 months), and purpose." }, 400, request);
    const income = Math.max(0, Math.round(Number(d.monthlyIncome||0)*100)), expenses = Math.max(0, Math.round(Number(d.monthlyExpenses||0)*100)), emi = Math.max(0, Math.round(Number(d.existingEmi||0)*100));
    const eligible = Math.max(0, Math.min(amount, Math.round(Math.max(0, income-expenses-emi)*tenure*0.3)));
    const id = uid();
    await env.DB.prepare("INSERT INTO loan_applications(id,user_id,requested_amount,tenure_months,purpose,monthly_income,monthly_expenses,existing_emi,eligible_suggestion) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(id,user.id,amount,tenure,String(d.purpose).trim(),income,expenses,emi,eligible).run();
    await audit(env,user,"loan_application_submitted","loan_application",id);
    return response({ ok:true, id, suggestedEligibility: eligible/100, message:"Demo application submitted for review." },201,request);
  }
  if (method === "GET" && path === "/api/loans") {
    const rows = user.role === "admin" ? await env.DB.prepare("SELECT l.*,u.display_name,u.username FROM loan_applications l JOIN users u ON u.id=l.user_id ORDER BY l.created_at DESC").all() : await env.DB.prepare("SELECT * FROM loan_applications WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return response({ applications: rows.results || [] },200,request);
  }
  if (method === "POST" && path === "/api/cards") {
    const d = await body(request), limit = Math.round(Number(d.requestedLimit)*100);
    if (!Number.isSafeInteger(limit) || limit < 10000 || limit > 100000000) return response({ error:"Enter a valid demo limit." },400,request);
    const income=Math.max(0,Math.round(Number(d.monthlyIncome||0)*100)), expenses=Math.max(0,Math.round(Number(d.monthlyExpenses||0)*100)), debt=Math.max(0,Math.round(Number(d.existingDebt||0)*100));
    const suggested=Math.max(0,Math.min(limit,Math.round(Math.max(0,income-expenses-debt)*3)));
    const id=uid();
    await env.DB.prepare("INSERT INTO card_applications(id,user_id,requested_limit,monthly_income,monthly_expenses,existing_debt,suggested_limit) VALUES(?,?,?,?,?,?,?)").bind(id,user.id,limit,income,expenses,debt,suggested).run();
    await audit(env,user,"card_application_submitted","card_application",id);
    return response({ok:true,id,suggestedLimit:suggested/100,message:"Demo card application submitted for review."},201,request);
  }
  if (method === "GET" && path === "/api/cards") {
    const rows = user.role === "admin" ? await env.DB.prepare("SELECT c.*,u.display_name,u.username FROM card_applications c JOIN users u ON u.id=c.user_id ORDER BY c.created_at DESC").all() : await env.DB.prepare("SELECT * FROM card_applications WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
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
    const loans = user.role === "admin"
      ? await env.DB.prepare("SELECT * FROM demo_loans ORDER BY created_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM demo_loans WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    const cards = user.role === "admin"
      ? await env.DB.prepare("SELECT * FROM virtual_cards ORDER BY created_at DESC LIMIT 500").all()
      : await env.DB.prepare("SELECT * FROM virtual_cards WHERE user_id=? ORDER BY created_at DESC").bind(user.id).all();
    return response({ loans: loans.results || [], cards: cards.results || [] }, 200, request);
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
    const id=uid(), amount=Number(loan.sanctioned_amount), tenure=Number(loan.tenure_months), monthly=Math.ceil(amount/tenure), group=uid();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO demo_loans(id,application_id,user_id,account_id,principal_amount,outstanding_amount,tenure_months,remaining_months,monthly_payment,status) VALUES(?,?,?,?,?,?,?,?,?,'active')").bind(id,loan.id,user.id,account.id,amount,amount,tenure,tenure,monthly),
      env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND user_id=?").bind(amount,account.id,user.id),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),account.id,group,"loan_disbursement",amount,Number(account.balance)+amount,"Demo loan disbursement"),
      env.DB.prepare("UPDATE loan_applications SET status='disbursed',updated_at=datetime('now') WHERE id=? AND user_id=? AND status='approved'").bind(loan.id,user.id)
    ]);
    await notify(env,user.id,"Demo loan activated",`N₹${(amount/100).toFixed(2)} demo loan added to your demo account. Monthly demo EMI: N₹${(monthly/100).toFixed(2)}.`);
    await audit(env,user,"demo_loan_disbursed","demo_loan",id,{applicationId:loan.id,amount,tenure});
    return response({ok:true,message:"Demo loan accepted and disbursed to your fictional account."},200,request);
  }

  const repayLoanMatch = path.match(/^\/api\/loans\/([^/]+)\/repay$/);
  if (method === "POST" && repayLoanMatch) {
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    const loan=await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND user_id=? AND status='active'").bind(repayLoanMatch[1],user.id).first();
    if(!loan) return response({error:"Active demo loan not found."},404,request);
    const account=await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=? AND status='active'").bind(loan.account_id,user.id).first();
    if(!account) return response({error:"No active account is available for repayment."},400,request);
    const amount=Math.min(Number(loan.monthly_payment),Number(loan.outstanding_amount));
    if(Number(account.balance)<amount) return response({error:`Insufficient demo balance. Your next demo EMI is N₹${(amount/100).toFixed(2)}.`},400,request);
    const outstanding=Math.max(0,Number(loan.outstanding_amount)-amount), remaining=outstanding===0?0:Math.max(0,Number(loan.remaining_months)-1), status=outstanding===0?"closed":"active", group=uid();
    await env.DB.batch([
      env.DB.prepare("UPDATE accounts SET balance=balance-? WHERE id=? AND user_id=? AND balance>=?").bind(amount,account.id,user.id,amount),
      env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),account.id,group,"loan_repayment",amount,Number(account.balance)-amount,"Demo loan EMI repayment"),
      env.DB.prepare("UPDATE demo_loans SET outstanding_amount=?,remaining_months=?,status=?,updated_at=datetime('now') WHERE id=? AND user_id=?").bind(outstanding,remaining,status,loan.id,user.id),
      ...(outstanding===0?[env.DB.prepare("UPDATE loan_applications SET status='closed',updated_at=datetime('now') WHERE id=? AND user_id=?").bind(loan.application_id,user.id)]:[])
    ]);
    await notify(env,user.id,"Demo EMI recorded",`Your demo EMI payment of N₹${(amount/100).toFixed(2)} was recorded. Remaining outstanding: N₹${(outstanding/100).toFixed(2)}.`);
    await audit(env,user,"demo_loan_repayment","demo_loan",loan.id,{amount,outstanding,remaining});
    return response({ok:true,message:`Demo EMI paid. Remaining outstanding: N₹${(outstanding/100).toFixed(2)}.`},200,request);
  }
  if (method === "POST" && path.startsWith("/api/admin/")) {
    if (user.role !== "admin") return response({error:"Admin permission required."},403,request);
    const d = await body(request);
    const loanMatch = path.match(/^\/api\/admin\/loans\/([^/]+)\/review$/);
    if (loanMatch) {
      const status=String(d.status||""), allowed=["need_documents","verified","approved","rejected"];
      if (!allowed.includes(status)) return response({error:"Invalid review status."},400,request);
      const amount = d.sanctionedAmount == null ? null : Math.round(Number(d.sanctionedAmount)*100);
      const loan=await env.DB.prepare("SELECT * FROM loan_applications WHERE id=?").bind(loanMatch[1]).first();
      if(!loan) return response({error:"Application not found."},404,request);
      if(status==="approved" && (!Number.isSafeInteger(amount)||amount<100||amount>loan.requested_amount)) return response({error:"Approved amount must be positive and not exceed requested amount."},400,request);
      await env.DB.prepare("UPDATE loan_applications SET status=?,sanctioned_amount=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status,amount,String(d.note||""),loan.id).run();
      await notify(env,loan.user_id,"Loan application update",`Your demo loan application status is now: ${status}. ${String(d.note||"")}`);
      await audit(env,user,"loan_review","loan_application",loan.id,{status,amount,note:d.note||""});
      return response({ok:true},200,request);
    }
    const cardMatch = path.match(/^\/api\/admin\/cards\/([^/]+)\/review$/);
    if (cardMatch) {
      const status=String(d.status||""), allowed=["need_documents","verified","approved","rejected"];
      if(!allowed.includes(status)) return response({error:"Invalid review status."},400,request);
      const amount=d.sanctionedLimit==null?null:Math.round(Number(d.sanctionedLimit)*100);
      const card=await env.DB.prepare("SELECT * FROM card_applications WHERE id=?").bind(cardMatch[1]).first();
      if(!card) return response({error:"Application not found."},404,request);
      if(status==="approved"&&(!Number.isSafeInteger(amount)||amount<100||amount>card.requested_limit)) return response({error:"Approved limit must be positive and not exceed requested limit."},400,request);
      await env.DB.prepare("UPDATE card_applications SET status=?,sanctioned_limit=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status,amount,String(d.note||""),card.id).run();
      if(status==="approved") {
        const finalLimit = Number(amount);
        const suffix = String(card.id).replace(/[^a-z0-9]/gi,"").slice(-4).toUpperCase().padStart(4,"0");
        await env.DB.prepare("INSERT INTO virtual_cards(id,user_id,masked_number,credit_limit,outstanding,status) VALUES(?,?,?,?,0,'active') ON CONFLICT(id) DO UPDATE SET credit_limit=excluded.credit_limit,status='active'").bind(card.id,card.user_id,`•••• •••• •••• ${suffix}`,finalLimit).run();
      }
      await notify(env,card.user_id,"Virtual card application update",`Your demo card application status is now: ${status}. ${String(d.note||"")}`);
      await audit(env,user,"card_review","card_application",card.id,{status,amount,note:d.note||""});
      return response({ok:true},200,request);
    }
  }
  if (method === "GET" && path === "/api/notifications") {
    const rows=await env.DB.prepare("SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
    return response({notifications:rows.results||[]},200,request);
  }
  if (method === "GET" && path === "/api/admin/audit") {
    if(user.role!=="admin") return response({error:"Admin permission required."},403,request);
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
      return new Response(JSON.stringify({ error: "Unexpected server error. Check Worker logs." }), { status: 500, headers: { "content-type": "application/json", "cache-control": "no-store", ...corsHeaders(request) } });
    }
  }
};
