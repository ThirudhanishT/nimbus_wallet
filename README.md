# Nimbus Wallet + PostgreSQL

This package keeps the existing Nimbus Wallet UI and replaces user/wallet persistence with a Node.js + Express + PostgreSQL API.

## 1. Create PostgreSQL database

Create a database named `nimbus_wallet` in PostgreSQL, then run `backend/schema.sql`.

## 2. Configure backend

Copy `backend/.env.example` to `backend/.env` and set:

- `DATABASE_URL`
- `JWT_SECRET`
- `CLIENT_ORIGIN` (for example `http://localhost:5500`)

Then:

```bash
cd backend
npm install
npm run dev
```

## 3. Serve the frontend

Do not open the HTML with `file://`. Use a local HTTP server. For example, from the project folder:

```bash
npx http-server . -p 5500
```

Open `http://localhost:5500/frontend.html`.

The frontend calls `http://localhost:5000/api` by default. Change `API_BASE` near the top of the JavaScript if your API runs elsewhere.

## What is stored in PostgreSQL

- users and bcrypt password hashes
- wallet balance
- PIN hash
- profile data
- biometric metadata
- transactions/rewards/notifications/budgets in the user's state

The browser may still use localStorage for UI-only preferences such as language/theme and the JWT session token. Wallet/account data is no longer the source of truth in localStorage.
