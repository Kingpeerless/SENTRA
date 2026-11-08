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

The Threat Lab uses synthetic scenarios. It does not currently attack a live AI agent or invoke an LLM.

### Authorization and Audit
Prepare eligible saved transactions, manage short-lived one-time authorization tokens, revoke issued intents, and maintain audit records.

### NEAR Testnet Verification
The backend includes a read-only verifier that checks submitted transaction hashes against NEAR Testnet RPC data.

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

The backend listens on `127.0.0.1:3001`. Keep the generated token in the backend process environment and enter it on the SENTRA access screen. Do not put it in frontend/Vite environment variables or commit it. The access screen keeps the token in memory only; logging out or reloading the page clears it.

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

For a production-mode backend, build the TypeScript output before installing only runtime dependencies:

```sh
cd backend
npm ci
npm run build
npm prune --omit=dev
npm start
```

Inject `SENTRA_ACCESS_TOKEN` using the host's secret manager or runtime secret configuration, and provide the same value to operators out-of-band. `GET /api/health` is the only public API route; every other `/api` route, including `GET /api/auth/verify`, requires the shared bearer token. Without a configured token, protected routes return HTTP 503. The backend binds to loopback by default. Keep the service and any same-origin `/api` proxy on a trusted private host/network, and do not publish the backend port or expose it publicly. Vite's proxy applies only to local development; production hosting must preserve the same-origin `/api` route without making the backend directly reachable from the public internet.

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

- The backend uses one shared bearer token for API access; it does not provide individual user identities or roles and must not be exposed publicly.
- Reviewer identity is not authenticated; a shared token does not establish a reviewer's personal identity.
- Wallet connection and Testnet account existence do not prove the wallet's active network. The dashboard therefore displays the active wallet network as **UNVERIFIED**.
- The current frontend does not sign, broadcast or execute transactions.
- Authorization preparation does not mean a transaction has been executed.
- Threat Lab scenarios are deterministic simulations rather than attacks on a live AI agent.
- The NEAR Testnet verifier checks submitted transaction hashes; it does not submit transactions.

SENTRA must not be represented as production-ready transaction execution infrastructure.

## Project Status
The current implementation demonstrates deterministic transaction security, agent identity binding, authorization preparation and revocation, approval workflows, audit records, and synthetic attack simulations.

Further work is required before production deployment or unrestricted wallet signing.

---

**SENTRA — Trust is not assumed. It is enforced.**
