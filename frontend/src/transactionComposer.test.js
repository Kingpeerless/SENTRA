import assert from "node:assert/strict";
import test from "node:test";
import {
  loadTransactionReviewData,
  nearToYocto,
  submitTransactionEvaluation,
  validateRecipient,
} from "./transactionComposer.ts";

function jsonResponse(payload, status = 201) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function evaluationPayload(decision, triggeredRules, approval = null) {
  return {
    data: {
      transactionId: `transaction-${decision.toLowerCase()}`,
      decisionId: `decision-${decision.toLowerCase()}`,
      decision,
      reasons: triggeredRules.map((rule) => `Rule explanation for ${rule}.`),
      triggeredRules,
      policyVersion: "policy-v1",
      approval,
      executed: false,
    },
  };
}

test("validates recipient account IDs and rejects invalid values", () => {
  assert.equal(validateRecipient(" recipient.testnet "), "recipient.testnet");
  for (const invalid of ["", "A.testnet", "x", "recipient@testnet", `${"a".repeat(65)}`]) {
    assert.throws(() => validateRecipient(invalid), /valid NEAR account ID/);
  }
});

test("converts positive decimal NEAR amounts exactly to yoctoNEAR", () => {
  assert.equal(nearToYocto("1"), "1000000000000000000000000");
  assert.equal(nearToYocto("0.000000000000000000000001"), "1");
  assert.equal(nearToYocto("2.50"), "2500000000000000000000000");
  for (const invalid of ["-1", "1e2", "1,2", "1.1234567890123456789012345"]) {
    assert.throws(() => nearToYocto(invalid), /positive NEAR amount/);
  }
  assert.throws(() => nearToYocto("0"), /greater than zero/);
  assert.throws(() => nearToYocto("0.0"), /greater than zero/);
});

test("submits a native Testnet transfer through the existing evaluation API and persists the result", async () => {
  let requestedUrl = "";
  let requestOptions;
  const evaluation = await submitTransactionEvaluation(
    { agentId: "agent-1", recipient: "recipient.testnet", amountNear: "0.5" },
    async (url, options) => {
      requestedUrl = String(url);
      requestOptions = options;
      return jsonResponse(evaluationPayload("ALLOW", ["POLICY_PASSED"]));
    },
  );
  assert.equal(requestedUrl, "/api/transactions/evaluate");
  assert.equal(requestOptions.method, "POST");
  assert.deepEqual(JSON.parse(requestOptions.body), {
    agentId: "agent-1",
    transaction: {
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "500000000000000000000000",
      asset: "NEAR",
      reason: "Operator-submitted transaction evaluation",
    },
  });
  assert.equal(evaluation.decision, "ALLOW");
  assert.equal(evaluation.executed, false);
  assert.deepEqual(evaluation.triggeredRules, ["POLICY_PASSED"]);
});

test("does not submit invalid recipient or amount to the API", async () => {
  let fetchCalls = 0;
  const fetchImplementation = async () => {
    fetchCalls += 1;
    return jsonResponse(evaluationPayload("ALLOW", ["POLICY_PASSED"]));
  };
  await assert.rejects(
    submitTransactionEvaluation({
      agentId: "agent-1",
      recipient: "bad recipient",
      amountNear: "1",
    }, fetchImplementation),
    /valid NEAR account ID/,
  );
  await assert.rejects(
    submitTransactionEvaluation({
      agentId: "agent-1",
      recipient: "recipient.testnet",
      amountNear: "NaN",
    }, fetchImplementation),
    /positive NEAR amount/,
  );
  assert.equal(fetchCalls, 0);
});

test("displays WARN only with a pending human approval record and never approves it automatically", async () => {
  const result = await submitTransactionEvaluation(
    { agentId: "agent-1", recipient: "recipient.testnet", amountNear: "2" },
    async () => jsonResponse(evaluationPayload("WARN", ["APPROVAL_REQUIRED"], {
      id: "approval-1",
      status: "pending",
    })),
  );
  assert.deepEqual(result.approval, { id: "approval-1", status: "pending" });
});

test("keeps BLOCK as a persisted non-authorizable decision", async () => {
  const result = await submitTransactionEvaluation(
    { agentId: "agent-1", recipient: "recipient.testnet", amountNear: "11" },
    async () => jsonResponse(evaluationPayload("BLOCK", ["MAX_AMOUNT_EXCEEDED"])),
  );
  assert.equal(result.decision, "BLOCK");
  assert.equal(result.approval, null);
});

test("refreshes the saved transaction list and approval records after evaluation", async () => {
  const savedTransaction = {
    id: "transaction-allow",
    agentId: "agent-1",
    network: "near-testnet",
    transactionType: "native_transfer",
    recipient: "recipient.testnet",
    amountYocto: "500000000000000000000000",
    asset: "NEAR",
    status: "ALLOW",
    createdAt: "2026-01-01T00:00:00.000Z",
    decision: {
      id: "decision-allow",
      decision: "ALLOW",
      reasons: ["Policy passed."],
      triggeredRules: ["POLICY_PASSED"],
      policyVersion: "policy-v1",
      createdAt: "2026-01-01T00:00:00.000Z",
    },
  };
  let calls = 0;
  const data = await loadTransactionReviewData(async (url) => {
    calls += 1;
    if (url === "/api/transactions") return jsonResponse({ data: [savedTransaction] }, 200);
    if (url === "/api/approvals") return jsonResponse({ data: [] }, 200);
    throw new Error(`Unexpected request: ${url}`);
  });
  assert.equal(calls, 2);
  assert.deepEqual(data.transactions, [savedTransaction]);
  assert.deepEqual(data.approvals, []);
});
