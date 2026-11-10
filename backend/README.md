# SENTRA backend

## Local API and database

Run `npm run dev` from this directory. The backend stores its SQLite database at `backend/data/sentra.sqlite` by default. Set `DATABASE_PATH` to use a different local file. The server uses `PORT` when set (default `3001`), binds to `127.0.0.1` locally, and binds to `0.0.0.0` when `NODE_ENV=production`.

## Shared access token

Every `/api` route except `GET /api/health` requires `Authorization: Bearer <token>`. Set `SENTRA_ACCESS_TOKEN` in the backend process environment before starting the server. Generate a unique, high-entropy value (for example, `openssl rand -hex 32`) and provide it through your operating system's secret manager or deployment secret facility. Do not commit it, put it in frontend/Vite configuration, or include it in logs. The operator enters the same value on the SENTRA access screen; the frontend holds it in memory only.

If `SENTRA_ACCESS_TOKEN` is unset or empty, protected API requests fail with HTTP 503; the public health endpoint remains available. Missing or invalid request credentials receive HTTP 401. Authentication uses a shared operator credential and does not provide individual identities or roles. On Render, the web service is publicly reachable over HTTPS, but all business/API routes require the shared token; keep the token secret and do not treat this as production-grade identity or transaction-execution security.

The checked-in `.gitignore` excludes `.env` files, a `secrets/` directory, and common key/secret-file extensions. Prefer runtime secret injection over local secret files.

## Build and deployment

For a standalone production-mode backend install, build while development dependencies are available, then remove them and start the compiled output:

```sh
npm ci
npm run build
npm prune --omit=dev
npm start
```

Inject `SENTRA_ACCESS_TOKEN` and, if needed, `DATABASE_PATH` through the runtime environment before `npm start`. If the built frontend exists at `../frontend/dist`, the backend serves it and the API from the same origin. The Vite `/api` proxy remains for local development.

## Render deployment

The repository-level `render.yaml` configures one Render free web service. The build command builds `frontend` before `backend`; the start command runs `npm start` from this directory. The backend binds to `0.0.0.0` and uses Render's `PORT`. Configure `SENTRA_ACCESS_TOKEN` as a Render secret and keep it out of frontend/Vite variables.

Render sets `DATABASE_PATH=./data/sentra.sqlite`, relative to the backend working directory. Render free web-service storage is ephemeral: SQLite data may disappear on restart, redeploy, or service replacement. The Blueprint does not configure persistent disks, paid services, or external databases. Do not rely on this deployment for durable records or production transaction execution.

Routes use `{ "data": ... }` for successful API responses and `{ "error": { "code": ..., "message": ... } }` for errors. Available routes:

- `GET /api/health`
- `GET /api/auth/verify` (protected; verifies the bearer token)
- `GET|POST /api/agents`
- `GET|PATCH /api/agents/:agentId`
- `GET|PUT /api/agents/:agentId/policy`
- `POST /api/transactions/evaluate`
- `POST /api/transactions/:transactionId/prepare`
- `POST /api/authorization-intents/:intentId/revoke`
- `POST /api/transactions/confirm`
- `GET /api/transactions` and `GET /api/transactions/:transactionId`
- `GET /api/approvals` and `GET /api/approvals/:approvalId`
- `POST /api/approvals/:approvalId/approve`
- `POST /api/approvals/:approvalId/reject`
- `GET /api/audit`
- `GET /api/threat-lab/scenarios`
- `POST /api/threat-lab/simulate`

Threat Lab uses deterministic, synthetic attack scenarios; it does not call an LLM or execute a transaction. Results are stored separately from transaction records and include the policy version used. Recipient substitution is blocked only if the substituted recipient is present in that agent's saved denylist; an ALLOW result demonstrates this policy configuration gap.

Transaction evaluation accepts an `agentId` and a `transaction` proposal. The proposal does not supply a policy; evaluation always uses the registered agent's saved policy.

```json
{
  "agentId": "registered-agent-id",
  "transaction": {
    "network": "near-testnet",
    "transactionType": "native_transfer",
    "recipient": "recipient.testnet",
    "amountYocto": "1000000000000000000000000",
    "asset": "NEAR",
    "reason": "Demonstration transfer"
  }
}
```

The shared bearer token gates the API, but the approval reviewer field remains a local hackathon demonstration value. It is not tied to an individual identity, and this API does not provide user roles.

Approving a pending WARN records a local review decision only. It does not sign, broadcast, or execute a blockchain transaction. SENTRA's local demo also does not prevent users from bypassing this application and transferring directly through their own wallets.

Preparation accepts no transaction overrides; it rechecks the saved decision and returns a one-time token for an eligible ALLOW or approved WARN intent. Confirmation accepts only the intent ID, token, and submitted transaction hash. The backend derives the expected signer, recipient, and amount from saved records, verifies against NEAR Testnet, and records the result. A verified result means the finalized chain transaction matched the expected native transfer; ALLOW or preparation alone does not mean a transaction was signed, broadcast, or executed. RPC pending, unavailable, or indeterminate results are not success.

Revocation requires the original one-time token in the request body; an intent ID alone cannot revoke it. An issued intent is revoked atomically, is recorded in the append-only audit log, and cannot proceed to verification. Revocation is not available once verification has started or after expiry. The frontend clears its in-memory token immediately and makes one best-effort revocation request when wallet/account/agent identity changes or an intent is replaced; if the request cannot be confirmed, the intent may remain valid until expiry.

The wallet connector does not provide trustworthy active-network identity. SENTRA therefore displays the wallet network as **UNVERIFIED** even when the connector requests Testnet or the account exists on Testnet. No wallet-signing operation is implemented or should be enabled while active network identity cannot be independently verified.

The backend binds to `0.0.0.0` as required by Render. A Render web service is publicly reachable over HTTPS; the health check is unauthenticated and all other API routes require the shared bearer token. A shared token is not a substitute for individual user identity, roles, or a full production security review. Do not use this demo service for production-sensitive workflows.

## Provision an agent's NEAR testnet wallet binding

Wallet bindings are provisioned locally using the backend CLI; there is no HTTP endpoint for changing them. From the repository root, run:

```sh
npm run provision-wallet --prefix backend -- <agent-id> <near-testnet-account-id>
```

For example:

```sh
npm run provision-wallet --prefix backend -- 3dc48e95-2d55-49c7-8ba0-4b890e4d026a sentra-agent.testnet
```

The CLI uses `DATABASE_PATH` when set, otherwise it opens `backend/data/sentra.sqlite` when run from the backend directory (run with `npm run provision-wallet -- <agent-id> <near-testnet-account-id>` from `backend/`). It displays the agent ID, current binding, and requested account before applying the change. Replacing an existing binding requires typing `REPLACE`; changing a binding invalidates outstanding authorization intents. Database uniqueness prevents one NEAR account from being bound to multiple agents, and each successful change is recorded in the append-only audit log.

This local provisioning tool does not authenticate an operator or prove control of the NEAR account. Do not treat possession of a SENTRA agent ID as authentication. The CLI accepts only an account ID; never provide private keys, seed phrases, or wallet credentials. This remains a local hackathon demonstration, not production access control.

Transaction decisions do not currently have an independent age-based expiry policy. Preparation checks that the saved decision still matches the current policy and transaction data; the three-minute expiry applies to authorization intents only. SENTRA does not claim that an older decision is invalid solely because of its age.
