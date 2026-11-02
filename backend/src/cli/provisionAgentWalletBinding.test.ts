import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateTransaction } from "../engine/policyEngine.js";
import { SentraDatabase } from "../database/database.js";
import { provisionAgentWalletBinding } from "./provisionAgentWalletBinding.js";

function withDatabase(run: (database: SentraDatabase) => Promise<void>): Promise<void> {
  const directory = mkdtempSync(join(tmpdir(), "sentra-wallet-cli-test-"));
  const database = new SentraDatabase(join(directory, "test.sqlite"));
  return run(database).finally(() => {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  });
}

test("provisions a valid account binding and records its audit event", async () => {
  await withDatabase(async (database) => {
    const { agent } = database.createAgent("Provisioning test agent", "");
    await provisionAgentWalletBinding(database, agent.id, "authorized.testnet", async () => {
      assert.fail("An unbound agent must not require replacement confirmation.");
    });

    assert.equal(
      database.getAgent(agent.id)?.authorizedNearAccountId,
      "authorized.testnet",
    );
    assert.ok(
      database.listAudit().some(
        (event) =>
          event.entityId === agent.id &&
          event.eventType === "agent.near_account_binding_changed",
      ),
    );
  });
});

test("rejects malformed account IDs and unknown agents", async () => {
  await withDatabase(async (database) => {
    const { agent } = database.createAgent("Provisioning test agent", "");

    await assert.rejects(
      provisionAgentWalletBinding(database, agent.id, "..", async () => true),
      /Invalid NEAR testnet account ID/,
    );
    await assert.rejects(
      provisionAgentWalletBinding(database, "missing-agent", "authorized.testnet", async () => true),
      /Unknown SENTRA agent/,
    );
  });
});

test("database uniqueness rejects binding an account already assigned elsewhere", async () => {
  await withDatabase(async (database) => {
    const first = database.createAgent("First agent", "").agent;
    const second = database.createAgent("Second agent", "").agent;
    await provisionAgentWalletBinding(database, first.id, "shared.testnet", async () => true);

    await assert.rejects(
      provisionAgentWalletBinding(database, second.id, "shared.testnet", async () => true),
      /UNIQUE constraint failed/,
    );
    assert.equal(database.getAgent(second.id)?.authorizedNearAccountId, null);
  });
});

test("existing binding replacement requires explicit confirmation", async () => {
  await withDatabase(async (database) => {
    const { agent } = database.createAgent("Replacement test agent", "");
    database.setAgentAuthorizedNearAccount(agent.id, "current.testnet");
    let confirmationAsked = false;

    await assert.rejects(
      provisionAgentWalletBinding(
        database,
        agent.id,
        "replacement.testnet",
        async () => {
          confirmationAsked = true;
          return false;
        },
      ),
      /confirmation required/,
    );
    assert.equal(confirmationAsked, true);
    assert.equal(database.getAgent(agent.id)?.authorizedNearAccountId, "current.testnet");
  });
});

test("replacement confirmation cannot overwrite a binding changed during the prompt", async () => {
  await withDatabase(async (database) => {
    const { agent } = database.createAgent("Concurrent replacement agent", "");
    database.setAgentAuthorizedNearAccount(agent.id, "current.testnet");

    await assert.rejects(
      provisionAgentWalletBinding(
        database,
        agent.id,
        "requested.testnet",
        async () => {
          database.setAgentAuthorizedNearAccount(agent.id, "changed.testnet");
          return true;
        },
      ),
      /binding changed; review the current binding and retry/,
    );
    assert.equal(database.getAgent(agent.id)?.authorizedNearAccountId, "changed.testnet");
  });
});

test("confirmed replacement invalidates outstanding intents and appends audit events", async () => {
  await withDatabase(async (database) => {
    const { agent, policy } = database.createAgent("Intent replacement agent", "");
    database.setAgentAuthorizedNearAccount(agent.id, "current.testnet");
    const transaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "1",
      asset: "NEAR",
      reason: "Replacement invalidation test",
    };
    const result = evaluateTransaction(transaction, agent, {
      version: policy.version,
      maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policy.approvalThresholdYocto,
      deniedRecipients: policy.deniedRecipients,
    });
    const evaluation = database.createEvaluation({
      agentId: agent.id,
      transaction,
      result,
      policy,
    });
    const intent = database.createAuthorizationIntent({
      transactionId: evaluation.transactionId,
      decisionId: evaluation.decisionId,
      approvalId: null,
      tokenHash: "e".repeat(64),
      policyId: policy.id,
      policyVersion: policy.version,
      authorizedWalletAccountId: "current.testnet",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });

    await provisionAgentWalletBinding(
      database,
      agent.id,
      "replacement.testnet",
      async () => true,
    );

    assert.equal(database.getAgent(agent.id)?.authorizedNearAccountId, "replacement.testnet");
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "stale");
    const audit = database.listAudit();
    assert.ok(
      audit.some(
        (event) =>
          event.eventType === "agent.near_account_binding_changed" &&
          event.entityId === agent.id,
      ),
    );
    assert.ok(
      audit.some(
        (event) =>
          event.eventType === "authorization_intent.stale" &&
          event.entityId === intent.id &&
          event.details.reason === "wallet_binding_changed",
      ),
    );
  });
});
