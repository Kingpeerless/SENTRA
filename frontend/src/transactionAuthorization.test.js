import assert from "node:assert/strict";
import test from "node:test";
import { setAccessToken } from "./apiAccess.ts";
import {
  canPrepareSavedTransaction,
  clearTemporaryAuthorizationToken,
  expireTemporaryAuthorizationToken,
  formatYoctoNear,
  getWarnApprovalStatus,
  parseApprovalsResponse,
  parseTransactionsResponse,
  prepareSavedTransaction,
  revokeAuthorizationIntent,
  storeTemporaryAuthorizationToken,
  takeTemporaryAuthorizationToken,
  isSigningEligibleForNetwork,
} from "./transactionAuthorization.ts";

setAccessToken("frontend-test-token");

const transaction = {
  id: "tx-1",
  agentId: "agent-1",
  network: "near-testnet",
  transactionType: "native_transfer",
  recipient: "recipient.testnet",
  amountYocto: "1000000000000000000000000",
  asset: "NEAR",
  status: "WARN",
  createdAt: "2026-01-01T00:00:00.000Z",
  decision: {
    id: "decision-1",
    decision: "WARN",
    reasons: ["Approval required."],
    triggeredRules: ["APPROVAL_REQUIRED"],
    policyVersion: "policy-1",
    createdAt: "2026-01-01T00:00:00.000Z",
  },
};

const approval = {
  id: "approval-1",
  decisionId: "decision-1",
  status: "approved",
  transactionId: "tx-1",
  agentId: "agent-1",
  decision: "WARN",
  policyVersion: "policy-1",
  createdAt: "2026-01-01T00:00:00.000Z",
};

function jsonResponse(payload, status = 201) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("parses saved transaction data and rejects inconsistent decision outcomes", () => {
  assert.deepEqual(
    parseTransactionsResponse({ data: [transaction] }),
    [transaction],
  );
  assert.throws(
    () => parseTransactionsResponse({
      data: [{ ...transaction, status: "ALLOW" }],
    }),
    /inconsistent saved transaction decision/,
  );
});

test("only an approved record linked to the exact WARN decision and policy is eligible", () => {
  const approvals = parseApprovalsResponse({ data: [approval] });
  assert.equal(getWarnApprovalStatus(transaction, approvals), "approved");
  assert.equal(canPrepareSavedTransaction(transaction, "approved"), true);
  assert.equal(getWarnApprovalStatus(transaction, []), "missing");
  assert.equal(canPrepareSavedTransaction(transaction, "missing"), false);

  for (const mismatch of [
    { transactionId: "other-tx" },
    { agentId: "other-agent" },
    { decisionId: "other-decision" },
    { policyVersion: "old-policy" },
    { status: "pending" },
    { status: "rejected" },
  ]) {
    const candidate = { ...approval, ...mismatch };
    const status = getWarnApprovalStatus(transaction, [candidate]);
    assert.notEqual(status, "approved");
    assert.equal(canPrepareSavedTransaction(transaction, status), false);
  }
});

test("BLOCK, unsupported network, type, and asset cannot be prepared", () => {
  assert.equal(
    canPrepareSavedTransaction({
      ...transaction,
      status: "BLOCK",
      decision: { ...transaction.decision, decision: "BLOCK" },
    }, "approved"),
    false,
  );
  for (const override of [
    { network: "near-mainnet" },
    { transactionType: "function_call" },
    { asset: "USDC" },
  ]) {
    assert.equal(canPrepareSavedTransaction({ ...transaction, ...override }, "approved"), false);
  }

  assert.equal(
    canPrepareSavedTransaction({
      ...transaction,
      status: "ALLOW",
      decision: { ...transaction.decision, decision: "ALLOW" },
    }, "missing"),
    true,
  );
});

test("prepares by saved transaction ID only and returns the validated token for volatile storage", async () => {
  const token = "A".repeat(43);
  const expiresAt = new Date(Date.now() + 180_000).toISOString();
  const intentResponse = {
    data: {
      intentId: "intent-1",
      authorizationToken: token,
      expiresAt,
      policyVersion: "policy-1",
      expectedSignerAccountId: "agent.testnet",
      recipient: "recipient.testnet",
      amountYocto: "1000000000000000000000000",
      approval: { status: "approved", reviewerIdentityVerified: false },
      executed: false,
    },
  };
  let requestedUrl = "";
  let requestOptions;
  const prepared = await prepareSavedTransaction("tx/one", async (url, options) => {
    requestedUrl = String(url);
    requestOptions = options;
    return jsonResponse(intentResponse);
  });

  assert.equal(requestedUrl, "/api/transactions/tx%2Fone/prepare");
  assert.equal(requestOptions.method, "POST");
  assert.deepEqual(JSON.parse(requestOptions.body), {});
  assert.deepEqual(prepared, {
    intentId: "intent-1",
    authorizationToken: token,
    expiresAt,
    policyVersion: "policy-1",
    expectedSignerAccountId: "agent.testnet",
    recipient: "recipient.testnet",
    amountYocto: "1000000000000000000000000",
    approval: { status: "approved", reviewerIdentityVerified: false },
    executed: false,
  });
  assert.equal(prepared.authorizationToken, token);
  const { authorizationToken, ...metadata } = prepared;
  assert.equal(JSON.stringify(metadata).includes(authorizationToken), false);
});

test("rejects expired or invalid authorization preparation responses before token storage", async () => {
  for (const [authorizationToken, expiresAt] of [
    ["A".repeat(43), new Date(Date.now() - 1).toISOString()],
    ["invalid-token", new Date(Date.now() + 60_000).toISOString()],
  ]) {
    await assert.rejects(
      prepareSavedTransaction("tx-1", async () => jsonResponse({
        data: {
          intentId: "intent-invalid",
          authorizationToken,
          expiresAt,
          policyVersion: "policy-1",
          expectedSignerAccountId: "agent.testnet",
          recipient: "recipient.testnet",
          amountYocto: "1",
          approval: null,
          executed: false,
        },
      })),
      /malformed authorization preparation data/,
    );
  }
});

test("stores the token in a volatile ref and replaces the previous intent token", () => {
  const tokenRef = { current: null };
  const first = {
    intentId: "intent-1",
    authorizationToken: "A".repeat(43),
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
    expectedSignerAccountId: "agent-1.testnet",
  };
  const second = {
    ...first,
    intentId: "intent-2",
    authorizationToken: "B".repeat(43),
  };

  assert.equal(storeTemporaryAuthorizationToken(tokenRef, first, "tx-1", "agent-1"), null);
  assert.equal(tokenRef.current.token, first.authorizationToken);
  assert.equal(storeTemporaryAuthorizationToken(tokenRef, second, "tx-2", "agent-2"), "intent-1");
  assert.equal(tokenRef.current.intentId, "intent-2");
  assert.equal(tokenRef.current.token, second.authorizationToken);
});

test("refuses to store an invalid or expired token", () => {
  const tokenRef = { current: null };
  const base = {
    intentId: "intent-1",
    authorizationToken: "E".repeat(43),
    expiresAt: new Date(Date.now() - 1).toISOString(),
    expectedSignerAccountId: "agent.testnet",
  };
  assert.throws(
    () => storeTemporaryAuthorizationToken(tokenRef, base, "tx-1", "agent-1"),
    /invalid or expired/,
  );
  assert.equal(tokenRef.current, null);
});

test("expires and clears temporary tokens without recovering or persisting them", () => {
  const tokenRef = {
    current: {
      intentId: "intent-expired",
      transactionId: "tx-1",
      agentId: "agent-1",
      expectedSignerAccountId: "agent.testnet",
      token: "C".repeat(43),
      expiresAt: 1000,
    },
  };
  assert.equal(expireTemporaryAuthorizationToken(tokenRef, 999), null);
  assert.equal(expireTemporaryAuthorizationToken(tokenRef, 1000), "intent-expired");
  assert.equal(tokenRef.current, null);
  const refreshedSessionRef = { current: null };
  assert.equal(refreshedSessionRef.current, null);
});

test("wallet disconnect, account change, agent change, consumption and invalidation clear the token", () => {
  for (const reason of [
    "wallet-disconnected",
    "account-changed",
    "agent-changed",
    "consumed",
    "invalidated",
    "session-ended",
  ]) {
    const tokenRef = {
      current: {
        intentId: "intent-1",
        transactionId: "tx-1",
        agentId: "agent-1",
        expectedSignerAccountId: "agent.testnet",
        token: "D".repeat(43),
        expiresAt: Date.now() + 60_000,
      },
    };
    assert.equal(clearTemporaryAuthorizationToken(tokenRef, reason), "intent-1");
    assert.equal(tokenRef.current, null);
  }
});

test("clears the token before best-effort server revocation and does not expose it in the URL", async () => {
  const token = "R".repeat(43);
  const tokenRef = {
    current: {
      intentId: "intent-revoke",
      transactionId: "tx-1",
      agentId: "agent-1",
      expectedSignerAccountId: "agent.testnet",
      token,
      expiresAt: Date.now() + 60_000,
    },
  };
  const captured = takeTemporaryAuthorizationToken(tokenRef, "wallet-disconnected");
  assert.equal(tokenRef.current, null);
  assert.equal(captured.token, token);

  let requestUrl = "";
  let requestOptions;
  const revoked = await revokeAuthorizationIntent(
    captured.intentId,
    captured.token,
    async (url, options) => {
      requestUrl = String(url);
      requestOptions = options;
      return jsonResponse({
        data: {
          intentId: captured.intentId,
          status: "revoked",
          revokedAt: new Date().toISOString(),
        },
      }, 200);
    },
  );
  assert.equal(revoked.status, "revoked");
  assert.match(requestUrl, /\/api\/authorization-intents\/intent-revoke\/revoke$/);
  assert.equal(requestUrl.includes(token), false);
  assert.equal(requestOptions.method, "POST");
  assert.deepEqual(JSON.parse(requestOptions.body), { authorizationToken: token });
});

test("revocation failures are generic and do not restore the cleared token", async () => {
  const token = "S".repeat(43);
  const tokenRef = {
    current: {
      intentId: "intent-revoke-failure",
      transactionId: "tx-1",
      agentId: "agent-1",
      expectedSignerAccountId: "agent.testnet",
      token,
      expiresAt: Date.now() + 60_000,
    },
  };
  const captured = takeTemporaryAuthorizationToken(tokenRef, "account-changed");
  await assert.rejects(
    revokeAuthorizationIntent(captured.intentId, captured.token, async () =>
      jsonResponse({ error: { code: "INVALID_AUTHORIZATION_TOKEN", message: token } }, 401),
    ),
    (error) => {
      assert.equal(error.message.includes(token), false);
      return /could not confirm authorization revocation/.test(error.message);
    },
  );
  assert.equal(tokenRef.current, null);
});

test("an unverified active wallet network is never signing-eligible", () => {
  assert.equal(isSigningEligibleForNetwork("unverified"), false);
  assert.equal(isSigningEligibleForNetwork("verified"), true);
});

test("surfaces stale, expired, rejected, and already-used API errors without retrying", async () => {
  for (const [code, message] of [
    ["STALE_DECISION", "Policy changed; re-evaluate the transaction before preparing."],
    ["APPROVAL_REQUIRED", "WARN requires approval."],
    ["PREVIOUS_INTENT_EXPIRED", "The prior authorization intent expired; create a new transaction evaluation before preparing again."],
    ["PREPARATION_EXISTS", "This transaction already has an authorization intent and cannot be prepared again."],
  ]) {
    await assert.rejects(
      prepareSavedTransaction("tx-1", async () => jsonResponse({ error: { code, message } }, 409)),
      (error) => error.code === code && error.message === message,
    );
  }
});

test("formats exact yoctoNEAR without floating-point conversion", () => {
  assert.equal(formatYoctoNear("1000000000000000000000000"), "1");
  assert.equal(formatYoctoNear("1000000000000000000000001"), "1.000000000000000000000001");
  assert.equal(formatYoctoNear("invalid"), null);
});
