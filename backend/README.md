# SENTRA backend

## Local API and database

Run `npm run dev` from this directory. The backend stores its SQLite database at `backend/data/sentra.sqlite` by default. Set `DATABASE_PATH` to use a different local file.

Routes use `{ "data": ... }` for successful API responses and `{ "error": { "code": ..., "message": ... } }` for errors. Available routes:

- `GET /api/health`
- `GET|POST /api/agents`
- `GET|PATCH /api/agents/:agentId`
- `GET|PUT /api/agents/:agentId/policy`
- `POST /api/transactions/evaluate`
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

The approval reviewer field is only a local hackathon demonstration value. This API has no production authentication or authorization, and a submitted reviewer name does not establish a real person's identity.

Approving a pending WARN records a local review decision only. It does not sign, broadcast, or execute a blockchain transaction. SENTRA's local demo also does not prevent users from bypassing this application and transferring directly through their own wallets.

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
