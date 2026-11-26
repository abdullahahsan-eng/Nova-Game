# NovaBank v8.2.0 – Compensation & Payroll Controls Edition

## Release contents
- Extends the v8.0.0 Staff Banking & Payroll foundation.
- Employee self-service is exposed through the employee's existing NovaBank customer login. Only the linked employee can view their own advance requests and payslips.
- Employees can request a salary advance with an amount, a per-payroll adjustment amount, and a reason.
- Super Admin can approve or reject requests. Approval checks Treasury funds, credits the employee's linked active account, records an account ledger entry, Treasury movement, notification and audit event.
- Approved advances are included in the next matching weekly/monthly payroll draft as an adjustment. Outstanding is reduced only when the payroll batch is paid.
- Paid payroll items generate immutable payslip snapshots with employee, period, earnings, deductions, advance adjustment, net pay, payment method/reference and unique payslip number.
- Employees and Super Admins can print payslips or use the browser print dialog's Save as PDF option. The layout is a professional A4 salary slip.
- Super Admin can archive and restore employees. Archived employees are excluded from new payroll batches and employee self-service; historical records remain.
- Payroll Control includes employee archive/restore, advance approvals and payslip archive.
- Customer, Super Admin and Branch Counter footers show v8.2.0.

## Files changed in this release
- `worker.js`
- `public/admin.html`
- `public/admin.js`
- `public/index.html`
- `public/app.js`
- `public/branch.html`
- `public/sw.js`
- `README.md`
- `PATCH_NOTES.md`

## D1 data safety
- No `DROP TABLE`, database reset, or destructive data migration is included.
- `payroll_employees` and `payroll_advances` are extended in place using additive `ensureColumn` migrations.
- `payroll_payslips` is created with `CREATE TABLE IF NOT EXISTS`.
- `schema.sql` and `wrangler.toml` are intentionally unchanged. Do not reset or recreate your D1 database and do not change its binding/database ID.
- Existing customer users, accounts, balances, transaction ledger, loans, cards and audit history are not intentionally rewritten by the schema migration.
- Employee archive is a soft archive. No permanent employee delete endpoint is provided.

## Workflow
1. Super Admin registers an existing customer and links their active savings account.
2. Employee signs in using their existing customer login and sees an Employee Payroll navigation item if an active employee record is linked.
3. Employee submits an advance request. Super Admin approves or rejects it in Payroll Control.
4. Approved advance is credited to the employee's linked active account after a Treasury funds check.
5. The next matching payroll draft includes the configured advance adjustment. Super Admin reviews payment method and reference and approves the batch.
6. On successful payroll execution, the advance outstanding is reduced and an immutable payslip snapshot is generated.
7. Employee or Super Admin selects Print / Save PDF and chooses Save as PDF in the browser dialog.
8. Super Admin can archive or restore an employee. Archiving does not delete payroll, payslip, advance, customer, account, or ledger history.

## Permissions
- Employee: own advance request, own advance status/history, own payslips.
- Super Admin: employee registration, archive/restore, advance approval/rejection, payroll batch creation/approval, all payslips.
- Employee self-service endpoints verify the authenticated user ID against the active employee record. Admin mutations require Super Admin.

## Validation performed
- `node --check` passed for `worker.js`, `public/admin.js`, `public/app.js`, `public/branch.js`, and `public/sw.js`.
- In-memory SQLite smoke test passed for existing `schema.sql`, additive payroll table/column migration, advance request/approval data flow, advance recovery on payroll, payslip snapshot persistence, and archive/restore history retention.
- Live Cloudflare Worker/D1 integration and browser print rendering were not available in this workspace. Test on a staging Worker and a demo employee before deploying broadly.

## Deploy carefully
1. Export/backup your current D1 database and keep a copy of your current repository.
2. Replace only the nine files listed above, preserving the repository folder structure.
3. Keep the existing `schema.sql`, `wrangler.toml`, D1 database ID/binding, secrets and all other environment settings unchanged.
4. Commit/push and deploy using your existing Cloudflare Worker/Assets workflow.
5. Test an advance request, Super Admin approval, linked account credit, payroll deduction, payroll execution, employee payslip PDF, archive and restore.
6. Do not run any database reset or destructive schema command.


## v8.2.0 – Compensation & Payroll Controls
- Added auditable compensation history and Super Admin salary-structure updates.
- Added per-period incentive and deduction controls on draft payroll items with net-pay and batch-total recalculation.
- Compensation changes are blocked while the employee has an open draft payroll item to avoid ambiguous snapshots.
- Additive D1 table only: `payroll_compensation_history`; no database reset or destructive migration.

## v8.2.0 compensation controls
- Recurring salary structure editor for basic salary, default incentive and default deductions, with effective date and mandatory reason.
- Additive `payroll_compensation_history` table with opening snapshot and immutable change history.
- Per-period incentive and deduction editing in draft payroll; net pay and batch totals recalculate.
- Salary structure updates are blocked while an affected employee has a draft payroll item.

## Files changed in this release
- `worker.js`
- `public/admin.html`
- `public/admin.js`
- `public/index.html`
- `public/branch.html`
- `README.md`
- `PATCH_NOTES.md`

## v10.0 / v10.1 — Nova Credit Intelligence & Nova QuickPay (implementation draft)
- Added additive tables for paid Credit Intelligence subscriptions, internal credit report snapshots, QuickPay beneficiaries, and idempotent QuickPay transfers.
- Credit Intelligence plans: ₹1,000 / 30 days, ₹4,500 / 180 days, ₹9,000 / 365 days. Detailed customer report is subscription-gated; score preview remains visible.
- Internal score range is 300–900 and is labelled as a simulator score, not CIBIL or a bureau score.
- Report includes utilization, loans, cards, applications, repayment records, late EMI count and suggested loan/card limits; browser print supports Save as PDF.
- QuickPay beneficiary verification starts a 10-minute cooling period. Transfers over ₹50,000 carry 0.5% on the full transfer amount. Fee is confirmed before payment; receipt is printable.
- QuickPay transfer requests carry a unique idempotency key to reduce duplicate payment risk.
- Existing tables are not dropped or rebuilt. Worker lazily creates feature tables; `migrations/001_credit_intelligence_quickpay.sql` is an optional additive migration for controlled deployment.
- This draft has not been tested against a live Cloudflare D1 database. Back up D1 and validate on a cloned database before deployment.

## Refund Management & Payment Confirmation Hardening (draft patch)
- Added Super Admin Refund Management API and screen for full/partial refunds against supported original debit ledger entries (`transfer_out`, `credit_report_subscription`, `quickpay_transfer_fee`).
- Refunds create separate `refund_credit` ledger entries and immutable refund audit records; original entries are retained.
- Transfer reversals also debit the matching recipient account and are blocked if the matching credit cannot be found or the recipient lacks available balance.
- Added subscription idempotency key storage and duplicate-response handling; customer plan buttons lock while a purchase is processing.
- Added a full-screen customer payment confirmation with print/save-PDF action for normal account transfer, QuickPay, subscription purchase, card-bill payment and loan-payment API success responses.
- Added a QuickPay submit lock and stable request key during retries.
- Added additive `transaction_refunds` table to migration 001. Worker also creates it lazily and adds the subscription idempotency column/index.
- Scope note: refund UI currently lists and processes the supported ledger types above. Loan/card repayment and card-bill reversals are deliberately not offered until linked product-balance reversal logic is implemented and tested.
- Validation completed locally: JavaScript syntax checks and SQLite additive migration smoke test. Live Cloudflare Worker/D1 deployment and end-to-end concurrent transaction tests remain outstanding.
