# SENTRA

### AI Agent Security Infrastructure
**AI can act. SENTRA keeps it accountable.**

SENTRA is a security gateway for AI-agent transactions. It evaluates proposed transactions against deterministic security policies before they can enter an authorization workflow.

Its purpose is simple: autonomous agents should not be trusted with unrestricted financial actions.

## The Problem
AI agents are increasingly capable of taking actions on behalf of users. However, autonomous execution introduces risks such as unauthorized transfers, manipulated instructions, recipient substitution, and spending-limit violations.

SENTRA introduces an independent policy enforcement layer between an AI agent's proposed action and transaction authorization.

## How SENTRA Works

1. An agent is registered and assigned a wallet identity.
2. A proposed transaction is evaluated against deterministic policies.
3. SENTRA returns one of three decisions:

   - **ALLOW:** The transaction passes configured policies.
   - **WARN:** Human approval is required.
   - **BLOCK:** The transaction violates a security rule and cannot be authorized.
4. Eligible transactions can enter a short-lived authorization preparation workflow.
5. Authorization events and security decisions are recorded for auditing.

AI instructions cannot override a deterministic BLOCK.

## Features

### Agent Registry
Register agents and associate them with provisioned NEAR wallet identities.

### Deterministic Policy Engine
Enforce spending limits, approval thresholds, agent status, recipient restrictions, supported network and asset rules.

### Transaction Firewall
Evaluate proposed native NEAR transfers and produce explainable ALLOW, WARN or BLOCK decisions.

### Human Approval Center
Review pending WARN decisions. Approvals in the current local demo are not authenticated human identities.

### Threat Lab
Run deterministic simulations covering:

- Spending-limit bypass
- Recipient substitution
- Policy override attempts
- Prompt injection

The Threat Lab uses the shared operator access token and runs deterministic simulations against saved agent policies. Results are persisted. It does not attack a live AI agent or invoke an LLM.

### Authorization and Audit
Prepare eligible saved transactions, manage short-lived one-time authorization tokens, revoke issued intents, and maintain audit records.

### NEAR Testnet Verification
The backend includes a read-only verifier that checks submitted transaction hashes against NEAR Testnet RPC data.

## Judge Access

**Live demo:** https://sentra-9wzc.onrender.com

The live dashboard is protected by a shared access token. For judge access, please email **kingpeerless080@gmail.com** with the subject **SENTRA — NEAR HACKATHON Judge Access**. Access credentials will be provided privately to judges.

The access token is intentionally not published in this repository. It grants access to protected API routes and must not be shared publicly.

### Suggested evaluation flow

1. Open the live demo and obtain the access token privately.
2. Explore the Agent Registry and review the registered agent.
3. Submit a transaction within the configured spending limit and observe the ALLOW decision.
4. Submit a transaction exceeding the limit and observe the BLOCK decision and explanation.
5. Open the Audit section to inspect recorded decisions.
6. Explore the Threat Lab to review the controlled security simulations.

The current implementation demonstrates deterministic policy evaluation and authorization workflows. It does not sign, broadcast, or execute transactions.

## Technology Stack

- React
- TypeScript
- Vite
- Node.js
- Express
- SQLite
- better-sqlite3
- Zod
- NEAR Testnet
- `@hot-labs/near-connect`

## Local Development
Requirements:

- Node.js 22+
- npm

Clone the repository and install dependencies.

**Backend**

```sh
cd backend
npm install
export SENTRA_ACCESS_TOKEN="$(openssl rand -hex 32)"
npm run dev
```

Locally, the backend listens on `127.0.0.1:3001`; in production (`NODE_ENV=production`) it binds to `0.0.0.0` and uses `PORT` when set. Keep the generated token in the backend process environment and enter it on the SENTRA access screen. Do not put it in frontend/Vite environment variables or commit it. The access screen keeps the token in memory only; logging out or reloading the page clears it.

**Frontend**

Open another terminal:

```sh
cd frontend
npm install
npm run dev
```

Open the Vite development address displayed in the terminal, normally:

```text
http://localhost:5173
```

The Vite development server proxies `/api` requests to the local backend.

## Render free web service

The repository includes [render.yaml](./render.yaml) for a single free web service. In Render, create a Blueprint from this repository and provide a high-entropy `SENTRA_ACCESS_TOKEN` when prompted. Keep the token in Render's environment settings and share it with operators out of band. It is read only by the backend and is never configured as a Vite variable or included in the frontend bundle.

The Blueprint builds the frontend first and then the backend; the backend serves `frontend/dist` and the `/api` routes from the same origin. It uses `PORT` provided by Render and binds to `0.0.0.0`. `DATABASE_PATH=./data/sentra.sqlite` is relative to the backend working directory. Render's free web-service filesystem is ephemeral: the SQLite database can be lost when the service restarts, redeploys, or is replaced. Do not use this deployment for durable records or funds-sensitive workflows. No persistent disk, paid service, or external database is configured.

To configure the same service manually, use:

```sh
npm ci --prefix frontend && npm run build --prefix frontend && npm ci --prefix backend && npm run build --prefix backend
```

Start command:

```sh
cd backend && npm start
```

Configure `SENTRA_ACCESS_TOKEN` and `DATABASE_PATH=./data/sentra.sqlite` in the Render environment. Render supplies `PORT`. `GET /api/health` remains public; every other `/api` route, including `GET /api/auth/verify`, requires the shared bearer token. If `SENTRA_ACCESS_TOKEN` is missing, protected routes fail closed with HTTP 503.

## Testing
Backend:

```sh
cd backend
npm test
npm run typecheck
```

Frontend:

```sh
cd frontend
npm test
npm run build
```

## Important Security Limitations
SENTRA is currently a local development and hackathon demonstration.

- The backend uses one shared bearer token for API access; it does not provide individual user identities or roles. A Render web service has a public HTTPS URL: only `GET /api/health` is unauthenticated, while every other API route requires the shared token.
- Reviewer identity is not authenticated; a shared token does not establish a reviewer's personal identity.
- Wallet connection and Testnet account existence do not prove the wallet's active network. The dashboard therefore displays the active wallet network as **UNVERIFIED**.
- The current frontend does not sign, broadcast or execute transactions.
- Authorization preparation does not mean a transaction has been executed.
- Threat Lab scenarios are deterministic simulations rather than attacks on a live AI agent.
- The NEAR Testnet verifier checks submitted transaction hashes; it does not submit transactions.
- Rendering the frontend and API on one origin does not add wallet signing, transaction execution protection, durable storage, or authenticated individual reviewer identities.

SENTRA must not be represented as production-ready transaction signing or execution-protection infrastructure. The Render free deployment is a publicly reachable demonstration service with shared-token API authentication and ephemeral SQLite storage; do not use it for production-sensitive or durable workflows.

## Project Status
The current implementation demonstrates deterministic transaction security, agent identity binding, authorization preparation and revocation, approval workflows, audit records, and synthetic attack simulations.

Further work is required before production deployment or unrestricted wallet signing.

---

**SENTRA — Trust is not assumed. It is enforced.**
