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
