# NovaBank queue and card lifecycle patch

## What changed
- Super Admin application lists normalize nullable DOM collections and use a cache-busted admin script URL (`admin-v21`).
- Loan/card active queues show only pending, need-documents, and verified applications.
- Existing approved/rejected applications with no archive timestamp are soft-archived automatically; rows are retained.
- The archive endpoint continues to show the original application records and decision notes.
- Card approval now creates a schema-valid `active` virtual card with `activation_pending=1` instead of writing the unsupported `inactive` status.
- Card activation uses `activation_pending` and records the existing N₹500 demo joining fee once.
- Pending-activation cards are excluded from card purchases, card transfers, and card-control actions.
- Customer portal shows the approved card and its activation action.
- Service worker cache version is bumped to v4 so the updated customer app can be fetched.

## Data safety
- No D1 database is dropped, recreated, or reset.
- No customer, account, balance, ledger, transaction, or application rows are deleted.
- Archive behavior uses `deleted_at` soft-archiving only.
- The Worker adds missing compatibility columns using `ensureColumn` and performs a small in-place migration for legacy final decisions and legacy inactive cards.

## Deploy
1. Review the changed files in this ZIP.
2. Replace the matching files in your repository, preserving any newer unrelated work.
3. Deploy the Worker using your existing Cloudflare configuration and D1 binding.
4. Deploy the Pages/static assets as you currently do.
5. Hard refresh the Super Admin page (Ctrl+Shift+R), then reopen Loan & Card Requests.
6. Test with a demo customer/application before using the workflow broadly.

## Validation performed
- `node --check` passed for `worker.js`, `public/admin.js`, and `public/app.js`.
- SQLite smoke test passed against `schema.sql` for legacy archive migration, card approval insert, and one-time activation state transition.
- Live Cloudflare/D1 integration was not available in this workspace, so deployment and authenticated end-to-end behavior still need to be verified in your account.
