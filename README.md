# NovaBank v8.2.0 – Compensation & Payroll Controls Edition

Fictional banking simulator built on Cloudflare Workers and D1. This release adds employee self-service salary advances, Super Admin approvals, advance recovery through payroll, immutable payslip snapshots with professional browser PDF/print output, and employee archive/restore.

## Employee workflow
1. Super Admin registers an existing active NovaBank customer as an employee and links their active savings account.
2. The employee signs in through the existing customer portal. The **Employee Payroll** navigation item appears only when an active employee record is linked to that signed-in customer.
3. Employee submits a salary advance request with amount, per-payroll adjustment and reason.
4. Super Admin approves/rejects in Payroll Control. Approval checks Treasury funds and credits the employee's linked active account.
5. The next matching weekly/monthly payroll draft includes the configured advance adjustment.
6. Super Admin reviews payment method/reference and executes the payroll batch.
7. The paid payroll item generates an immutable payslip snapshot. Employee and Super Admin can select Print / Save PDF and choose Save as PDF in the browser print dialog.
8. Super Admin can archive/restore employees. Archived employees are excluded from new payroll runs; historical data is retained.

## Data and deployment safety
- Preserve your existing Cloudflare D1 database, database ID and binding.
- Do not drop, recreate, reset or reseed D1.
- `schema.sql` and `wrangler.toml` are unchanged in this patch.
- Worker applies additive payroll migrations with `CREATE TABLE IF NOT EXISTS` and `ensureColumn`.
- Replace only the nine files listed in `PATCH_NOTES.md`; keep all other repository files and Cloudflare settings.
- Back up D1 and test on a staging Worker before broad deployment.

## Access control
- Employee self-service is tied to the existing customer login and can access only the authenticated employee's own payroll records.
- Only Super Admin can approve/reject advances, archive/restore employees, create/approve payroll batches and access the full payslip archive.

## Validation limitations
JavaScript syntax checks and local SQLite migration/workflow smoke tests passed. Live Cloudflare D1 integration and browser print rendering were not available in this environment; verify those in your staging deployment.


## v8.2.0 – Compensation & Payroll Controls
- Super Admin can revise recurring basic salary, incentive and deductions with effective date and reason; changes are audited and apply to future payroll drafts.
- Draft payroll items support period-specific one-time incentive and deduction edits; batch totals recalculate.
- Compensation history is stored in an additive table. Existing customer, account, ledger and payroll history is preserved.

## Compensation controls (v8.2.0)
- Super Admin can revise recurring basic salary, incentive and deductions from each active employee card. Each change requires an effective date (not later than today) and a reason.
- Changes are blocked while the employee has an open draft payroll item, and apply to future drafts only.
- A compensation audit history preserves opening salary values and each later revision.
- During draft payroll review, Super Admin can set period-specific one-time incentive and deduction values per employee. Net pay and the batch total recalculate before approval.
