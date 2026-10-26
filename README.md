# BigDaddy GAME — Next.js Administration Starter

A usable admin console for **non-redeemable game points**, game/player management, lawful-business manual accounting, public USDT wallet **address registry**, and non-executable payout draft records.

## Start

Install Node 22+ and run:

```bash
npm install
cp .env.example .env
```

Edit `.env` and set your own `ADMIN_EMAIL`, strong `ADMIN_PASSWORD`, and a random `SESSION_SECRET` (32+ characters). Do not commit `.env`.

```bash
npm run dev
```

Open http://localhost:3000 and sign in using the credentials you set. SQLite database initializes automatically in `./data` on first request.

## Features
- Admin login with bcrypt password hash, signed HttpOnly/SameSite session cookie
- Overview with player/game counters, manual accounting profit and loss, activity trend, latest audit actions
- Player registration with unique `game_id`
- Game creation and enable/disable
- Atomic signed point adjustments by `game_id`, enforced nonnegative balances and immutable ledger records
- Manual lawful business financial entries: revenue, expense, deposit and refund, kept in integer paise
- USDT public wallet address registry (ERC-20 and TRC-20 formats), deactivation preserves history
- Non-executable USDT payout **drafts** and cancellation. **No on-chain transfers or approvals.**
- Audit log for actions

## Limits and security
This is a local-development starter, **not production-certified**. Before deploying: add persistent database-backed sessions, IP-based rate limiting, two-factor authentication, CSRF defenses appropriate to the hosting setup, admin role separation, proper migrations, centralized audit retention, backup and restore, automated tests, transaction idempotency, reconciled double-entry bookkeeping, independent security review, HTTPS and secrets management. Use PostgreSQL when deploying across serverless instances. SQLite on Vercel ephemeral disk is not durable.

The app does not connect to game clients, payment providers, blockchain RPC endpoints or exchanges. No private keys, seed phrases, custody, token transfers or cashable player credits are supported. Wallet address validation checks basic format only, not chain existence, checksums, ownership or sanctions compliance. Payout drafts are records only; they do not reserve financial balances or represent actual liabilities.

**Legal:** Do not use this to operate prohibited real-money online gaming or facilitate related financial transfers. Verify local laws and obtain compliance advice before implementing financial operations.

## API routes
`GET /api/me`, `POST /api/login`, `POST /api/logout`

Authenticated `GET`: `overview`, `players`, `games`, `points`, `entries`, `wallets`, `payouts`, `audit`.

Authenticated `POST`: `players`, `games`, `games/status`, `points`, `entries`, `wallets`, `wallets/deactivate`, `payouts`, `payouts/cancel`.

All routes prefixed `/api/`.
