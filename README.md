NovaBank Super Admin Portal v7
================================
This is an extension of the uploaded v6 Worker and portal, not a replacement for wrangler.toml or the existing D1 database.

New in v7:
- Dedicated Super Admin sections: overview, customer lookup, deposit/withdrawal queue, loan/card applications, offer management, active loans/cards, ledger and audit.
- Portfolio snapshot: customer balances, approved deposits/withdrawals, demo loans disbursed, principal/outstanding, repayments/foreclosures, card limits and card outstanding.
- Customer-targeted offers. Offers with no assignment rows are global; once an offer is assigned to one or more customers, only those customers see it. Use a targeted offer for private promotions.
- API endpoints added: GET /api/admin/summary, GET /api/admin/offers/:id/assignments, POST /api/admin/offers/:id/assign.
- Existing customer details and one-time loan foreclosure are retained.

Deploy:
1. Back up current worker and public folder.
2. Replace root worker.js with this file.
3. Copy public/admin.html, public/admin.js, public/admin.css into existing public folder. Preserve index.html and other assets.
4. Keep existing wrangler.toml, DB D1 binding, ASSETS binding, secrets and D1 database.
5. Deploy Worker.
6. Open /admin.html and sign in with Super Admin credentials.

Important:
- Do not create a new database.
- This is a fictional simulator, not a real bank.
- No real deposits, real money, payment rails, or actual financial services.
- Admin and API flows need testing against a backup/test account before relying on them.
- Summary amounts are derived from demo ledger and simulated product tables; they are not a statement of actual bank capital/reserves.
