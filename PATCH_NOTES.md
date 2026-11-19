# NovaBank v8.0.0 – Staff Banking & Payroll Edition

## Base retained
This release is built on the uploaded NovaBank Super Admin Portal v7 package. Existing customer portal, account, loan, card, ledger, Treasury, branch counter, staff/security and application workflows are retained.

## Added in v8.0.0
- Super Admin Payroll Control Centre.
- Employee directory linked to an existing NovaBank customer user and that customer's active account. Employee numbers are generated as `NB-EMP-0001` style identifiers.
- Monthly and weekly employee salary frequency.
- Salary structure fields for basic salary, default bonus/incentives and deductions. All money is stored in the existing minor-unit convention (100 units = N₹1.00).
- Draft payroll batches with period dates, employee count and total net salary.
- Per-employee payment method selection: internal NovaBank account transfer or manual/external payment reference.
- Super Admin-only approval or rejection. Approval checks the current Treasury balance, records internal salary credits in the customer's existing account ledger, marks payroll items paid, posts payroll expense to Treasury, sends employee notifications and writes audit events.
- Version footer in Customer, Super Admin and Branch Counter portals.
- Additive runtime D1 tables: `payroll_employees`, `payroll_batches`, `payroll_items`, `payroll_advances`. Existing tables and records are not dropped or reset.

## Important scope limitations
This is the first payroll foundation, not the complete HR/staff self-service suite. It does **not** yet include a separate employee login/portal, HR-generated employee customer-account application/approval flow, attendance, downloadable payslips, advance creation/adjustment workflow, or full payroll reversal/correction workflow. The advances table is reserved but no advance-entry UI is enabled. Do not treat the presence of that table as an implemented feature.

Employee registration currently requires a verified existing customer User ID and active account number. The employee remains a customer identity for account credit; this release does not issue separate employee credentials.

## Data safety
- Do not create, rename, reset, or replace the existing D1 database.
- Keep the existing `wrangler.toml`, D1 database binding, secrets and environment settings.
- Payroll tables are created additively when the Super Admin opens Payroll Control Centre.
- Existing customer balances and transaction history are not intentionally migrated or rewritten.
- Internal salary payments credit the employee's existing NovaBank account. Manual/external payments only record an external reference and do not credit the employee's NovaBank account.
- Treasury payroll expense is recorded as a negative Treasury movement; Treasury funds are checked before execution.

## Files in this patch
- `worker.js`
- `public/admin.html`
- `public/admin.js`
- `public/index.html`
- `public/branch.html`
- `README.md`

## Validation performed
- `node --check worker.js` passed.
- `node --check public/admin.js` passed.
- `node --check public/branch.js` passed (unchanged file).
- Existing `schema.sql` and the new payroll table definitions executed successfully in an in-memory SQLite smoke test.
- Live Cloudflare Worker/D1 authenticated end-to-end testing was not available. Test on a backup/test deployment and a demo employee before production-like use.

## Deploy carefully
1. Back up the current repository and confirm the D1 database backup/export.
2. Replace only the listed files in your existing repository. Keep `schema.sql`, `wrangler.toml`, database ID/binding, secrets, and all other assets unless you intentionally merge other work.
3. Deploy the Worker and static assets using your existing deployment process.
4. Sign in to Super Admin and open Payroll Control.
5. Register a test employee using a test customer's User ID and active account number. Create a small draft batch and inspect the payment method/reference before approving.
6. Confirm the test customer's account ledger, Treasury history, notification and audit event. Never test by resetting the live D1 database.
