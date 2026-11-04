import assert from "node:assert/strict";
import test from "node:test";
import {
  getPendingWarnApprovals,
  reviewWarnApproval,
} from "./transactionApproval.ts";

const transaction = {
  id: "tx-warn",
  agentId: "agent-1",
  network: "near-testnet",
  transactionType: "native_transfer",
  recipient: "merchant.testnet",
  amountYocto: "2000000000000000000000000",
  asset: "NEAR",
  status: "WARN",
  createdAt: "2026-10-01T10:00:00.000Z",
  decision: {
    id: "decision-warn",
    decision: "WARN",
    reasons: ["Human approval is required."],
    triggeredRules: ["APPROVAL_REQUIRED"],
    policyVersion: "policy-2",
    createdAt: "2026-10-01T10:00:00.000Z",
  },
};

const approval = {
  id: "approval-1",
  decisionId: "decision-warn",
  status: "pending",
  transactionId: "tx-warn",
  agentId: "agent-1",
  decision: "WARN",
  policyVersion: "policy-2",
  createdAt: "2026-10-01T10:00:01.000Z",
};

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("lists only pending WARN approvals linked to the exact saved WARN decision", () => {
  const mismatches = [
    { status: "approved" },
    { decision: "BLOCK" },
    { transactionId: "other-tx" },
    { agentId: "other-agent" },
    { decisionId: "other-decision" },
    { policyVersion: "old-policy" },
  ];
  const transactions = [
    transaction,
    {
      ...transaction,
      id: "tx-block",
      status: "BLOCK",
      decision: { ...transaction.decision, id: "decision-block", decision: "BLOCK" },
    },
  ];

  assert.deepEqual(
    getPendingWarnApprovals(
      [approval, ...mismatches.map((mismatch, index) => ({
        ...approval,
        id: `mismatch-${index}`,
        ...mismatch,
      }))],
      transactions,
    ),
    [{ approval, transaction }],
  );
});

test("approves a matching WARN using the existing endpoint and labels reviewer as local demo", async () => {
  let requestUrl = "";
  let requestOptions;
  const result = await reviewWarnApproval(
    approval,
    transaction,
    "approve",
    "",
    async (url, options) => {
      requestUrl = String(url);
      requestOptions = options;
      return jsonResponse({
        data: { ...approval, status: "approved", decision: "WARN" },
      });
    },
  );

  assert.equal(requestUrl, "/api/approvals/approval-1/approve");
  assert.equal(requestOptions.method, "POST");
  assert.deepEqual(JSON.parse(requestOptions.body), {
    reviewer: "Local demo reviewer (unverified)",
  });
  assert.equal(result.status, "approved");
});

test("rejects a matching WARN only with a reason using the existing endpoint", async () => {
  let fetchCalls = 0;
  const fetchImplementation = async (url, options) => {
    fetchCalls += 1;
    assert.equal(url, "/api/approvals/approval-1/reject");
    assert.deepEqual(JSON.parse(options.body), {
      reviewer: "Local demo reviewer (unverified)",
      rejectionReason: "Recipient is not expected.",
    });
    return jsonResponse({
      data: { ...approval, status: "rejected", decision: "WARN" },
    });
  };

  await assert.rejects(
    reviewWarnApproval(approval, transaction, "reject", "  "),
    /Enter a reason/,
  );
  const result = await reviewWarnApproval(
    approval,
    transaction,
    "reject",
    " Recipient is not expected. ",
    fetchImplementation,
  );
  assert.equal(result.status, "rejected");
  assert.equal(fetchCalls, 1);
});

test("never sends review requests for BLOCK or mismatched approval records", async () => {
  let fetchCalls = 0;
  const fetchImplementation = async () => {
    fetchCalls += 1;
    return jsonResponse({ data: {} });
  };
  const blockTransaction = {
    ...transaction,
    status: "BLOCK",
    decision: { ...transaction.decision, decision: "BLOCK" },
  };

  await assert.rejects(
    reviewWarnApproval(approval, blockTransaction, "approve", "", fetchImplementation),
    /Only a pending WARN approval/,
  );
  await assert.rejects(
    reviewWarnApproval(
      { ...approval, policyVersion: "stale-policy" },
      transaction,
      "approve",
      "",
      fetchImplementation,
    ),
    /Only a pending WARN approval/,
  );
  assert.equal(fetchCalls, 0);
});

test("surfaces API errors and rejects malformed review responses", async () => {
  await assert.rejects(
    reviewWarnApproval(approval, transaction, "approve", "", async () =>
      jsonResponse({ error: { message: "Policy changed; re-evaluation is required." } }, 409),
    ),
    /Policy changed/,
  );
  await assert.rejects(
    reviewWarnApproval(approval, transaction, "approve", "", async () =>
      jsonResponse({ data: { ...approval, status: "rejected" } }),
    ),
    /invalid approval review result/,
  );
});
