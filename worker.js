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
async function ensureCardColumns(env) {
  await ensureColumn(env, "card_applications", "existing_emi", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "card_applications", "loan_outstanding", "INTEGER NOT NULL DEFAULT 0");
  await ensureColumn(env, "virtual_cards", "demo_number", "TEXT NOT NULL DEFAULT ''");
}
async function route(request, env) {
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request) });
  if (!path.startsWith("/api/")) return env.ASSETS.fetch(request);
  if (method === "GET" && path === "/api/health") return response({ ok: true, app: "NovaBank", mode: "fictional-simulator" }, 200, request);

  // Admin bootstrap endpoint removed after initial Super Admin creation.

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
  await env.DB.prepare(`CREATE TABLE IF NOT EXISTS product_closure_requests (
    id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), product_type TEXT NOT NULL CHECK(product_type IN ('loan','card')),
    product_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
    amount_paid INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL DEFAULT '', admin_note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT, reviewed_by TEXT REFERENCES users(id)
  )`).run();
  if (method === "GET" && path === "/api/closure-requests") {
    const rows = user.role === "admin"
      ? await env.DB.prepare(`SELECT r.*,u.display_name,u.username FROM product_closure_requests r JOIN users u ON u.id=r.user_id ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END,r.created_at DESC LIMIT 300`).all()
      : await env.DB.prepare("SELECT * FROM product_closure_requests WHERE user_id=? ORDER BY created_at DESC LIMIT 100").bind(user.id).all();
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
    await notify(env,user.id,"Loan closure awaiting review",`Full demo outstanding of N₹${(amount/100).toFixed(2)} has been paid. Admin confirmation is pending.`);
    await audit(env,user,"loan_closure_requested","demo_loan",loan.id,{requestId:reqId,amount});
    return response({ok:true,requestId:reqId,message:`Full payment recorded (N₹${(amount/100).toFixed(2)}). Loan will close after admin approval.`},201,request);
  }
  const cardClosure = path.match(/^\/api\/cards\/([^/]+)\/closure-request$/);
  if (method === "POST" && cardClosure) {
    const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status IN ('active','inactive','blocked')").bind(cardClosure[1],user.id).first();
    if(!card) return response({error:"Demo card not found or already closed."},404,request);
    if(Number(card.outstanding)>0) return response({error:`Please clear card dues of N₹${(Number(card.outstanding)/100).toFixed(2)} before requesting closure.`},400,request);
    const duplicate=await env.DB.prepare("SELECT id FROM product_closure_requests WHERE product_type='card' AND product_id=? AND status='pending'").bind(card.id).first();
    if(duplicate) return response({error:"A card closure request is already awaiting admin review."},409,request);
    const reqId=uid(); await env.DB.prepare("INSERT INTO product_closure_requests(id,user_id,product_type,product_id,status,note) VALUES(?,?, 'card',?,'pending','Outstanding is zero; awaiting admin closure approval')").bind(reqId,user.id,card.id).run();
    await env.DB.prepare("UPDATE virtual_cards SET status='closure_pending' WHERE id=? AND user_id=?").bind(card.id,user.id).run();
    await notify(env,user.id,"Card closure request submitted","Your demo card closure request is awaiting admin review.");
    await audit(env,user,"card_closure_requested","virtual_card",card.id,{requestId:reqId});
    return response({ok:true,requestId:reqId,message:"Card closure request submitted. It will disappear from Cards & Loans after admin approval."},201,request);
  }
  if (method === "GET" && path === "/api/me") return response({ user }, 200, request);

  // Super Admin: list customers and their demo accounts.
  if (method === "GET" && path === "/api/admin/summary") {
    if (user.role !== "admin") return response({error:"Admin permission required."},403,request);
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
    if (user.role !== "admin") return response({ error: "Admin permission required." }, 403, request);
    const q = String(url.searchParams.get("q") || "").trim().slice(0,100);
    const like = `%${q.replace(/[\%_]/g, "\\$&")}%`;
    const rows = await env.DB.prepare(`SELECT u.id AS user_id,u.username,u.display_name,u.email,u.role AS user_role,u.status AS user_status,u.created_at AS customer_since,
      a.id AS account_id,a.account_number,a.account_type,a.status AS account_status,a.balance,a.opened_at
      FROM users u LEFT JOIN accounts a ON a.user_id=u.id
      WHERE u.role!='admin' AND (?='' OR u.username LIKE ? ESCAPE '\\' OR u.display_name LIKE ? ESCAPE '\\' OR u.email LIKE ? ESCAPE '\\' OR a.account_number LIKE ? ESCAPE '\\')
      ORDER BY u.created_at DESC LIMIT 250`).bind(q,like,like,like,like).all();
    return response({ customers: rows.results || [] }, 200, request);
  }

  if (method === "GET" && path === "/api/admin/customer-details") {
    if (user.role !== "admin") return response({ error: "Admin permission required." }, 403, request);
    const customerId = String(url.searchParams.get("userId") || "").trim();
    if (!customerId) return response({ error: "Customer ID is required." }, 400, request);
    const customer = await env.DB.prepare("SELECT id,username,display_name,email,role,status,created_at FROM users WHERE id=? AND role!='admin'").bind(customerId).first();
    if (!customer) return response({ error: "Customer not found." }, 404, request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS demo_loans (
      id TEXT PRIMARY KEY, application_id TEXT NOT NULL UNIQUE REFERENCES loan_applications(id),
      user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      principal_amount INTEGER NOT NULL, outstanding_amount INTEGER NOT NULL,
      tenure_months INTEGER NOT NULL, remaining_months INTEGER NOT NULL,
      monthly_payment INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      created_at TEXT NOT NULL DEFAULT (datetime('now')), updated_at TEXT NOT NULL DEFAULT (datetime('now'))
    )`).run();
    const [accounts, loans, cards, loanApps, cardApps, tx] = await Promise.all([
      env.DB.prepare("SELECT * FROM accounts WHERE user_id=? ORDER BY opened_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM demo_loans WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT * FROM virtual_cards WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT id,requested_amount,tenure_months,sanctioned_amount,status,admin_note,created_at,updated_at FROM loan_applications WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT id,requested_limit,sanctioned_limit,status,admin_note,created_at,updated_at FROM card_applications WHERE user_id=? ORDER BY created_at DESC").bind(customerId).all(),
      env.DB.prepare("SELECT l.* FROM ledger l JOIN accounts a ON a.id=l.account_id WHERE a.user_id=? ORDER BY l.created_at DESC LIMIT 50").bind(customerId).all()
    ]);
    return response({ customer, accounts:accounts.results||[], loans:loans.results||[], cards:cards.results||[], loanApplications:loanApps.results||[], cardApplications:cardApps.results||[], transactions:tx.results||[] },200,request);
  }

  const accountStatusMatch = path.match(/^\/api\/admin\/accounts\/([^/]+)\/status$/);
  if (accountStatusMatch && method === "POST") {
    if (user.role !== "admin") return response({ error: "Admin permission required." }, 403, request);
    const d = await body(request), status = String(d.status || "");
    if (!['active','frozen'].includes(status)) return response({ error: "Choose active or frozen." }, 400, request);
    const account = await env.DB.prepare("SELECT a.*,u.id AS owner_id,u.display_name,u.username FROM accounts a JOIN users u ON u.id=a.user_id WHERE a.id=?").bind(accountStatusMatch[1]).first();
    if (!account) return response({ error: "Account not found." }, 404, request);
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
      : await env.DB.prepare("SELECT o.* FROM offers o WHERE o.active=1 AND (o.valid_until='' OR o.valid_until>=date('now')) AND (NOT EXISTS(SELECT 1 FROM offer_assignments oa WHERE oa.offer_id=o.id) OR EXISTS(SELECT 1 FROM offer_assignments oa WHERE oa.offer_id=o.id AND oa.user_id=?)) ORDER BY o.created_at DESC").bind(user.id).all();
    return response({ offers: rows.results || [] }, 200, request);
  }

  const offerAssignmentsMatch = path.match(/^\/api\/admin\/offers\/([^/]+)\/assignments$/);
  if (offerAssignmentsMatch && method === "GET") {
    if (user.role !== "admin") return response({error:"Admin permission required."},403,request);
    const rows = await env.DB.prepare("SELECT oa.user_id,u.display_name,u.username FROM offer_assignments oa JOIN users u ON u.id=oa.user_id WHERE oa.offer_id=? ORDER BY u.display_name").bind(offerAssignmentsMatch[1]).all();
    return response({users:rows.results||[]},200,request);
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
    const rows = user.role === "admin"
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
    if (user.role !== 'admin') return response({error:"Admin permission required."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    const rows=await env.DB.prepare("SELECT r.*,u.display_name,u.username,a.account_number FROM money_requests r JOIN users u ON u.id=r.user_id JOIN accounts a ON a.id=r.account_id ORDER BY CASE r.status WHEN 'pending' THEN 0 WHEN 'processing' THEN 1 ELSE 2 END,r.created_at DESC LIMIT 300").all();
    return response({requests:rows.results||[]},200,request);
  }
  const moneyReview = path.match(/^\/api\/admin\/money-requests\/([^/]+)\/review$/);
  if (moneyReview && method === "POST") {
    if (user.role !== 'admin') return response({error:"Admin permission required."},403,request);
    await env.DB.prepare(`CREATE TABLE IF NOT EXISTS money_requests (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), account_id TEXT NOT NULL REFERENCES accounts(id),
      type TEXT NOT NULL CHECK(type IN ('deposit','withdrawal')), amount INTEGER NOT NULL CHECK(amount > 0),
      description TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','processing','approved','rejected')),
      admin_note TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL DEFAULT (datetime('now')), reviewed_at TEXT,
      reviewed_by TEXT REFERENCES users(id), review_token TEXT
    )`).run();
    const d=await body(request), status=String(d.status||''), note=String(d.note||'').trim().slice(0,250);
    if(!['approved','rejected'].includes(status)) return response({error:'Choose approve or reject.'},400,request);
    const r=await env.DB.prepare("SELECT * FROM money_requests WHERE id=?").bind(moneyReview[1]).first();
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
    await notify(env,r.user_id,'Money request approved',`${r.type==='deposit'?'Deposit':'Withdrawal'} request ${r.id} approved. N₹${(amount/100).toFixed(2)} demo balance ${r.type==='deposit'?'credited':'debited'}.`);
    await audit(env,user,'money_request_approved','money_request',r.id,{type:r.type,amount,accountId:r.account_id,transactionGroup:group,note});
    return response({ok:true,message:`Request ${r.id} approved. Demo balance updated to N₹${(nextBalance/100).toFixed(2)}.`},200,request);
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
    const id=uid();
    await env.DB.prepare("INSERT INTO card_applications(id,user_id,requested_limit,monthly_income,monthly_expenses,existing_debt,suggested_limit,existing_emi,loan_outstanding) VALUES(?,?,?,?,?,?,?,?,?)")
      .bind(id,user.id,0,income,expenses,debt,suggested,emi,loanOutstanding).run();
    await audit(env,user,"card_application_submitted","card_application",id,{income,expenses,existingEmi:emi,existingCardDebt:debt,loanOutstanding,suggestedLimit:suggested});
    return response({ok:true,id,suggestedLimit:suggested/100,message:"Demo card application submitted for bank assessment."},201,request);
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

    const closureReview = path.match(/^\/api\/admin\/closure-requests\/([^/]+)\/review$/);
    if (closureReview) {
      const status=String(d.status||""), note=String(d.note||"").trim().slice(0,250);
      if(!["approved","rejected"].includes(status)) return response({error:"Choose approve or reject."},400,request);
      const r=await env.DB.prepare("SELECT * FROM product_closure_requests WHERE id=? AND status='pending'").bind(closureReview[1]).first();
      if(!r) return response({error:"Pending closure request not found."},404,request);
      if(r.product_type==='loan') {
        const loan=await env.DB.prepare("SELECT * FROM demo_loans WHERE id=? AND user_id=? AND status='closure_pending'").bind(r.product_id,r.user_id).first();
        if(!loan) return response({error:"Loan is no longer awaiting closure."},409,request);
        if(status==='approved') {
          await env.DB.batch([
            env.DB.prepare("UPDATE demo_loans SET outstanding_amount=0,remaining_months=0,status='closed',updated_at=datetime('now') WHERE id=? AND status='closure_pending'").bind(loan.id),
            env.DB.prepare("UPDATE loan_applications SET status='closed',updated_at=datetime('now') WHERE id=? AND user_id=?").bind(loan.application_id,r.user_id)
          ]);
        } else {
          const acct=await env.DB.prepare("SELECT * FROM accounts WHERE id=? AND user_id=?").bind(loan.account_id,r.user_id).first();
          if(!acct) return response({error:"Linked demo account not found; cannot safely reverse payment."},409,request);
          const group=uid(),amount=Number(r.amount_paid),after=Number(acct.balance)+amount;
          await env.DB.batch([
            env.DB.prepare("UPDATE accounts SET balance=balance+? WHERE id=? AND user_id=?").bind(amount,acct.id,r.user_id),
            env.DB.prepare("INSERT INTO ledger(id,account_id,transaction_group,type,amount,balance_after,description) VALUES(?,?,?,?,?,?,?)").bind(uid(),acct.id,group,"loan_foreclosure_reversal",amount,after,"Reversal of rejected demo loan closure request"),
            env.DB.prepare("UPDATE demo_loans SET status='active',updated_at=datetime('now') WHERE id=? AND status='closure_pending'").bind(loan.id)
          ]);
        }
      } else {
        const card=await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=? AND status='closure_pending'").bind(r.product_id,r.user_id).first();
        if(!card) return response({error:"Card is no longer awaiting closure."},409,request);
        if(status==='approved') await env.DB.prepare("UPDATE virtual_cards SET status='closed' WHERE id=? AND user_id=? AND outstanding=0").bind(card.id,r.user_id).run();
        else await env.DB.prepare("UPDATE virtual_cards SET status='inactive' WHERE id=? AND user_id=? AND status='closure_pending'").bind(card.id,r.user_id).run();
      }
      await env.DB.prepare("UPDATE product_closure_requests SET status=?,admin_note=?,reviewed_at=datetime('now'),reviewed_by=? WHERE id=? AND status='pending'").bind(status,note,user.id,r.id).run();
      await notify(env,r.user_id,`${r.product_type==='loan'?'Loan':'Card'} closure ${status}`,status==='approved'?"Your demo product has been closed and removed from active products.":`Your closure request was rejected. ${note}`);
      await audit(env,user,`${r.product_type}_closure_${status}`,r.product_type,r.product_id,{requestId:r.id,note});
      return response({ok:true,message:`Closure request ${status}.`},200,request);
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
      await notify(env,loan.user_id,"Demo loan foreclosed",`Your demo loan ${loan.id} was fully paid through a one-time foreclosure payment of N₹${(amount/100).toFixed(2)}. Remaining balance is N₹0.00.`);
      await audit(env,user,"demo_loan_foreclosed","demo_loan",loan.id,{amount,accountId:account.id,transactionGroup:group,oneTimePayment:true});
      return response({ok:true,message:`Loan foreclosed with one-time demo payment of N₹${(amount/100).toFixed(2)}.`,paidAmount:amount/100,remainingOutstanding:0},200,request);
    }

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
      await ensureCardColumns(env);
      const status=String(d.status||""), allowed=["need_documents","verified","approved","rejected"];
      if(!allowed.includes(status)) return response({error:"Invalid review status."},400,request);
      const amount=d.sanctionedLimit==null?null:Math.round(Number(d.sanctionedLimit)*100);
      const card=await env.DB.prepare("SELECT * FROM card_applications WHERE id=?").bind(cardMatch[1]).first();
      if(!card) return response({error:"Application not found."},404,request);
      if(status==="approved"&&(!Number.isSafeInteger(amount)||amount<100||amount>20000000)) return response({error:"Approved limit must be between N₹1 and N₹200,000."},400,request);
      await env.DB.prepare("UPDATE card_applications SET status=?,sanctioned_limit=?,admin_note=?,updated_at=datetime('now') WHERE id=?").bind(status,amount,String(d.note||""),card.id).run();
      if(status==="approved") {
        const finalLimit = Number(amount);
        const suffix = String(card.id).replace(/[^a-z0-9]/gi,"").slice(-4).toUpperCase().padStart(4,"0");
        const demoHash = await digest(card.id); const demoNumber = "9000" + demoHash.slice(0,12).replace(/[^0-9]/g,"7").padEnd(12,"7") + suffix;
        await env.DB.prepare("INSERT INTO virtual_cards(id,user_id,masked_number,credit_limit,outstanding,status,demo_number) VALUES(?,?,?,?,0,'inactive',?) ON CONFLICT(id) DO UPDATE SET credit_limit=excluded.credit_limit, status='inactive', demo_number=excluded.demo_number").bind(card.id,card.user_id,`•••• •••• •••• ${suffix}`,finalLimit,demoNumber).run();
      }
      await notify(env,card.user_id,"Virtual card application update",`Your demo card application status is now: ${status}. ${String(d.note||"")}`);
      await audit(env,user,"card_review","card_application",card.id,{status,amount,note:d.note||""});
      return response({ok:true},200,request);
    }
  }
  const cardActivateMatch = path.match(/^\/api\/cards\/([^/]+)\/activate$/);
  if (method === "POST" && cardActivateMatch) {
    await ensureCardColumns(env);
    const card = await env.DB.prepare("SELECT * FROM virtual_cards WHERE id=? AND user_id=?").bind(cardActivateMatch[1],user.id).first();
    if (!card) return response({error:"Virtual card not found."},404,request);
    if (card.status === "blocked") return response({error:"Blocked card must be unblocked by an admin."},400,request);
    await env.DB.prepare("UPDATE virtual_cards SET status='active' WHERE id=? AND user_id=?").bind(card.id,user.id).run();
    await audit(env,user,"demo_card_activated","virtual_card",card.id);
    return response({ok:true,message:"Demo card activated."},200,request);
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
    await audit(env,user,"demo_card_repayment","virtual_card",card.id,{amount});
    return response({ok:true,message:"Demo card repayment recorded."},200,request);
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
