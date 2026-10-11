NovaBank Super Admin Portal v6
================================
Files:
- worker.js: based on the uploaded worker(4).js, with setup-admin bootstrap route removed, customer detail endpoint added, and one-time demo loan foreclosure endpoint added.
- public/admin.html, public/admin.js, public/admin.css: dedicated Super Admin portal at /admin.html.
- schema.sql: not changed; the Worker creates demo_loans table if missing.

Deploy notes:
1. Back up the currently deployed worker.js and public assets.
2. Replace root worker.js with this worker.js.
3. Add public/admin.html, public/admin.js, public/admin.css to the same assets directory as the current public/index.html.
4. Preserve wrangler.toml, D1 binding DB, ASSETS binding and all existing customer data.
5. Deploy to Cloudflare.
6. After deploy, delete ADMIN_SETUP_KEY from Production variables/secrets; this worker no longer exposes /api/setup-admin.
7. Open https://YOUR-WORKER/admin.html and sign in with the created admin account.

Important behavior:
- Admin portal requires authenticated user.role === 'admin'; APIs enforce this server-side.
- Customer search supports name, username, email and account number.
- Account freeze/unfreeze requires a reason and uses existing admin API.
- Full one-time foreclosure deducts the complete outstanding amount from the customer's linked active demo account. It fails if the account has insufficient demo balance; it does not waive/write off debt.
- All amounts are fictional Nova Rupees; no real banking or payments.
- Validate in a test customer account before relying on it. Review the current production worker against this bundle before deploying if there have been changes after worker(4).js.
