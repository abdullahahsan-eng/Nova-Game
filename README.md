# NovaBank — Full Banking Simulator (Phase 1 foundation)

A fictional, educational banking simulator. It does **not** connect to real banks, UPI, card networks, payment gateways, or credit bureaus. All balances are demo-only Nova Rupees (N₹).

## Included in this package
- Responsive PWA-ready interface
- Cloudflare Worker API foundation
- Cloudflare D1 schema for users, accounts, sessions, ledger, loan applications, virtual-card applications, notifications, and audit events
- Password hashing using Web Crypto PBKDF2
- Register/login/logout and authenticated profile endpoints
- Account/transaction listing
- Demo loan and virtual-card application endpoints
- Admin-only review endpoints and admin bootstrap protected by a setup secret
- Transfer endpoint with basic balance checks and a D1 batch ledger pattern

## Important
This is a **Phase 1 development foundation**, not a finished production banking product. Before public use, the remaining workflows must be completed and tested: secure concurrent transfers/atomic ledger guarantees, document upload to private object storage, account recovery, rate limits, comprehensive role/permission checks, loan amortization, credit-card billing, recurring salary jobs, Central Bank controls, accessibility, and security testing. Do not store real identity documents or real financial data.

## Deploy (Cloudflare)
1. Create a GitHub repository and upload these files.
2. In Cloudflare, create a D1 database named `novabank-db`.
3. Copy the database ID into `wrangler.toml`.
4. Run `npx wrangler d1 execute novabank-db --remote --file=schema.sql`.
5. Set secrets:
   - `npx wrangler secret put SESSION_SECRET`
   - `npx wrangler secret put ADMIN_SETUP_KEY`
6. Install Wrangler and deploy with `npx wrangler deploy`.
7. Open the deployed Worker URL. The static assets are served from `public/` using the assets binding in `wrangler.toml`.
8. Bootstrap the first admin by sending a POST request to `/api/setup-admin` with JSON `{ "setupKey":"YOUR_ADMIN_SETUP_KEY", "username":"admin", "password":"a-strong-demo-password" }`. Remove/disable this endpoint after the admin is created.

## Local preview
Open `public/index.html` directly for the UI preview. API actions require deployment to Cloudflare. The UI is designed to show a clear connection status when the API is unavailable.

## Currency and roles
- Currency: N₹ (fictional only)
- Roles: customer and admin in this phase. The schema is ready for expansion to branch manager, loan officer, credit officer, cashier, and auditor.
