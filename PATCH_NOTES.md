# NovaBank v8.1.0 – HR & Payroll Management Edition

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
- Customer, Super Admin and Branch Counter footers show v8.1.0.

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
