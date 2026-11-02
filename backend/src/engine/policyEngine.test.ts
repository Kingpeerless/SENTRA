import assert from "node:assert/strict";
import test from "node:test";
import {
  DEFAULT_DEMONSTRATION_POLICY,
  evaluateTransaction,
  type Agent,
  type Policy,
  type Transaction,
} from "./policyEngine.js";

const enabledAgent: Agent = { id: "agent-1", enabled: true };
const NEAR = 10n ** 24n;

function transaction(overrides: Partial<Transaction> = {}): Transaction {
  return {
    agentId: enabledAgent.id,
    network: "near-testnet",
    transactionType: "native_transfer",
    recipient: "recipient.testnet",
    amountYocto: (NEAR / 2n).toString(),
    asset: "NEAR",
    reason: "Requested transfer",
    ...overrides,
  };
}

function evaluate(
  input: unknown,
  agent: Agent | undefined = enabledAgent,
  policy: Policy = DEFAULT_DEMONSTRATION_POLICY,
) {
  return evaluateTransaction(input, agent, policy);
}

function assertDecision(
  input: unknown,
  decision: "ALLOW" | "WARN" | "BLOCK",
  expectedRules: string[],
  agent: Agent | undefined = enabledAgent,
  policy: Policy = DEFAULT_DEMONSTRATION_POLICY,
) {
  const result = evaluate(input, agent, policy);
  assert.equal(result.decision, decision);
  assert.deepEqual(result.triggeredRules, expectedRules);
}

test("valid transfer below threshold is allowed", () => {
  assertDecision(transaction(), "ALLOW", ["POLICY_PASSED"]);
});

test("transfer exactly at approval threshold warns", () => {
  assertDecision(
    transaction({ amountYocto: (2n * NEAR).toString() }),
    "WARN",
    ["APPROVAL_REQUIRED"],
  );
});

test("transfer above approval threshold warns", () => {
  assertDecision(
    transaction({ amountYocto: (3n * NEAR).toString() }),
    "WARN",
    ["APPROVAL_REQUIRED"],
  );
});

test("transfer exactly at maximum warns", () => {
  assertDecision(
    transaction({ amountYocto: (10n * NEAR).toString() }),
    "WARN",
    ["APPROVAL_REQUIRED"],
  );
});

test("transfer above maximum is blocked", () => {
  assertDecision(
    transaction({ amountYocto: (10n * NEAR + 1n).toString() }),
    "BLOCK",
    ["MAX_AMOUNT_EXCEEDED"],
  );
});

test("disabled agent is blocked", () => {
  assertDecision(transaction(), "BLOCK", ["AGENT_DISABLED"], {
    id: enabledAgent.id,
    enabled: false,
  });
});

test("unknown agent is blocked", () => {
  const result = evaluateTransaction(transaction(), undefined);
  assert.equal(result.decision, "BLOCK");
  assert.deepEqual(result.triggeredRules, ["AGENT_NOT_FOUND"]);
});

test("denied recipient is blocked", () => {
  const policy: Policy = {
    ...DEFAULT_DEMONSTRATION_POLICY,
    deniedRecipients: ["recipient.testnet"],
  };
  assertDecision(transaction(), "BLOCK", ["RECIPIENT_DENIED"], enabledAgent, policy);
});

test("invalid recipient is blocked", () => {
  assertDecision(transaction({ recipient: "Bad..Account" }), "BLOCK", ["INVALID_RECIPIENT"]);
});

test("zero amount is blocked", () => {
  assertDecision(
    transaction({ amountYocto: "0" }),
    "BLOCK",
    ["INVALID_TRANSACTION", "INVALID_AMOUNT"],
  );
});

test("negative amount is blocked", () => {
  assertDecision(
    transaction({ amountYocto: "-1" }),
    "BLOCK",
    ["INVALID_TRANSACTION", "INVALID_AMOUNT"],
  );
});

test("decimal and malformed amounts are blocked", async (context) => {
  for (const amountYocto of ["1.5", "1e24", "not-an-integer"]) {
    await context.test(amountYocto, () => {
      assertDecision(
        transaction({ amountYocto }),
        "BLOCK",
        ["INVALID_TRANSACTION", "INVALID_AMOUNT"],
      );
    });
  }
});

test("unsupported network is blocked", () => {
  assertDecision(
    transaction({ network: "near-mainnet" }),
    "BLOCK",
    ["UNSUPPORTED_NETWORK"],
  );
});

test("unsupported asset is blocked", () => {
  assertDecision(transaction({ asset: "USDC" }), "BLOCK", ["UNSUPPORTED_ASSET"]);
});

test("unsupported transaction type is blocked", () => {
  assertDecision(
    transaction({ transactionType: "token_transfer" }),
    "BLOCK",
    ["UNSUPPORTED_TRANSACTION_TYPE"],
  );
});

test("all applicable rules are reported and BLOCK takes priority", () => {
  const policy: Policy = {
    ...DEFAULT_DEMONSTRATION_POLICY,
    deniedRecipients: ["recipient.testnet"],
  };
  assertDecision(
    transaction({ amountYocto: (11n * NEAR).toString() }),
    "BLOCK",
    ["RECIPIENT_DENIED", "MAX_AMOUNT_EXCEEDED"],
    enabledAgent,
    policy,
  );
});

test("invalid transaction structure is blocked without exposing its contents", () => {
  const result = evaluate({ arbitrary: "secret" });
  assert.equal(result.decision, "BLOCK");
  assert.deepEqual(result.triggeredRules, ["INVALID_TRANSACTION"]);
  assert.equal(result.evaluatedTransaction, null);
});

test("identical inputs produce identical decisions", () => {
  const input = transaction({ amountYocto: (2n * NEAR).toString() });
  assert.deepEqual(evaluate(input), evaluate(input));
});

test("default demonstration thresholds are exact yoctoNEAR integer strings", () => {
  assert.equal(DEFAULT_DEMONSTRATION_POLICY.approvalThresholdYocto, "2000000000000000000000000");
  assert.equal(
    DEFAULT_DEMONSTRATION_POLICY.maxTransactionAmountYocto,
    "10000000000000000000000000",
  );
});
