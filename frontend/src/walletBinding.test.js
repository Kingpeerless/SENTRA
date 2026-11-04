import assert from "node:assert/strict";
import test from "node:test";
import { getWalletBindingStatus, parseAgentsResponse } from "./walletBinding.ts";

const boundAgent = {
  id: "agent-1",
  name: "Bound agent",
  authorizedNearAccountId: "sentra-agent.testnet",
};

test("binding status reports a match", () => {
  assert.equal(getWalletBindingStatus(boundAgent, "sentra-agent.testnet"), "MATCH");
});

test("binding status reports a mismatch", () => {
  assert.equal(getWalletBindingStatus(boundAgent, "other-account.testnet"), "MISMATCH");
});

test("binding status reports an unbound agent", () => {
  assert.equal(
    getWalletBindingStatus({ ...boundAgent, authorizedNearAccountId: null }, "sentra-agent.testnet"),
    "NOT BOUND",
  );
});

test("binding status reports a disconnected wallet", () => {
  assert.equal(getWalletBindingStatus(boundAgent, null), "WALLET DISCONNECTED");
});

test("changing the selected agent recalculates the binding status", () => {
  const accountId = "sentra-agent.testnet";
  assert.equal(getWalletBindingStatus(boundAgent, accountId), "MATCH");
  assert.equal(
    getWalletBindingStatus(
      { ...boundAgent, id: "agent-2", authorizedNearAccountId: "other-account.testnet" },
      accountId,
    ),
    "MISMATCH",
  );
  assert.equal(
    getWalletBindingStatus(
      { ...boundAgent, id: "agent-3", authorizedNearAccountId: null },
      accountId,
    ),
    "NOT BOUND",
  );
});

test("changing the connected wallet recalculates the binding status", () => {
  assert.equal(getWalletBindingStatus(boundAgent, "sentra-agent.testnet"), "MATCH");
  assert.equal(getWalletBindingStatus(boundAgent, "changed-account.testnet"), "MISMATCH");
  assert.equal(getWalletBindingStatus(boundAgent, null), "WALLET DISCONNECTED");
});

test("parses the read-only agent API response and rejects malformed data", () => {
  assert.deepEqual(
    parseAgentsResponse({ data: [boundAgent] }),
    [boundAgent],
  );
  assert.deepEqual(
    parseAgentsResponse({ data: [{ ...boundAgent, enabled: false }] }),
    [{ ...boundAgent, enabled: false }],
  );
  assert.throws(
    () => parseAgentsResponse({ data: [{ ...boundAgent, enabled: "false" }] }),
    /malformed agent data/,
  );
  assert.throws(() => parseAgentsResponse({ data: [{ id: "bad" }] }), /malformed agent data/);
});
