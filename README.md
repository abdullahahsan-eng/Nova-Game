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


## NovaBank upgrade (November 2026)

- Adds readable, unique loan/card application numbers and exact customer tracking.
- Hides rejected/closed applications from the default customer request list while retaining rows for application-number lookup and admin search.
- Loan sanctions support a 5% processing fee plus ₹1,100 file charge deducted from the sanctioned principal; the net amount is credited to the customer account.
- EMI is calculated on sanctioned principal at 0% demo interest, with a persisted month-by-month schedule.
- Adds Super Admin application search and account-number-based manual deposit/withdrawal with ledger, Treasury, notification and audit entries.
- Adds customer notification display and printable fictional loan sanction letters.
- Fixes virtual-card approval to use the schema-supported `active` status with `activation_pending=1`.

The Worker applies additive D1 migrations at runtime. Do not delete or recreate the existing D1 database.


## Branch Counter and loan account numbers
- Activated demo loans receive a permanent `NVL-YYYY-XXXXXXXXXX` Loan Account Number.
- Authenticated customers can look up a loan and pay it from their own account, including another customer's loan.
- Partial payments are allocated oldest-installment-first and tracked in `loan_emi_schedule.paid_amount`; excess payment can cover following installments up to the outstanding balance.
- Staff with Cashier or Branch Manager permissions use `/branch.html` for cash deposit/withdrawal, loan collections, and credit-card bill collection. Super Admin can also access the Branch Counter.
- Credit-card lookup requires the cardholder account number plus card last four digits; full card number, CVV and PIN are never requested.
- Treasury reports inflow, outflow, ledger balance and a type-by-type collection/revenue breakdown.
- All features are fictional simulator operations in NVR/Nova Rupee; no real payments or financial instruments are created.
