import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { DEFAULT_DEMONSTRATION_POLICY, evaluateTransaction } from "../engine/policyEngine.js";
import { SentraDatabase } from "./database.js";

function withDatabase(run: (database: SentraDatabase) => void): void {
  const directory = mkdtempSync(join(tmpdir(), "sentra-db-test-"));
  const database = new SentraDatabase(join(directory, "test.sqlite"));
  try {
    run(database);
  } finally {
    database.close();
    rmSync(directory, { recursive: true, force: true });
  }
}

test("database initializes required tables and enables foreign keys", () => {
  withDatabase((database) => {
    const tables = database.connection
      .prepare("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name")
      .all()
      .map((row) => (row as { name: string }).name);

    assert.deepEqual(tables, [
      "agents",
      "approvals",
      "audit_logs",
      "decisions",
      "policies",
      "transactions",
    ]);
    assert.equal(database.connection.pragma("foreign_keys", { simple: true }), 1);
  });
});

test("agents and policies persist with default demonstration policy", () => {
  withDatabase((database) => {
    const created = database.createAgent("Test agent", "Temporary test agent");
    const agentId = created.agent.id;
    const policy = database.getCurrentPolicy(agentId);

    assert.deepEqual(database.getAgent(agentId), created.agent);
    assert.equal(policy?.version, "1");
    assert.equal(
      policy?.maxTransactionAmountYocto,
      DEFAULT_DEMONSTRATION_POLICY.maxTransactionAmountYocto,
    );
    assert.equal(
      policy?.approvalThresholdYocto,
      DEFAULT_DEMONSTRATION_POLICY.approvalThresholdYocto,
    );
    assert.deepEqual(policy?.deniedRecipients, []);
  });
});

test("records persist after closing and reopening the database", () => {
  const directory = mkdtempSync(join(tmpdir(), "sentra-db-reopen-test-"));
  const filename = join(directory, "persistent.sqlite");
  const firstConnection = new SentraDatabase(filename);
  const created = firstConnection.createAgent("Persistent agent", "");
  firstConnection.close();

  const reopened = new SentraDatabase(filename);
  try {
    assert.equal(reopened.getAgent(created.agent.id)?.name, "Persistent agent");
    assert.equal(reopened.getCurrentPolicy(created.agent.id)?.version, "1");
  } finally {
    reopened.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("foreign-key constraints reject child rows without parent records", () => {
  withDatabase((database) => {
    assert.throws(() => {
      database.connection
        .prepare(
          `INSERT INTO policies
            (id, agent_id, version, max_transaction_amount_yocto, approval_threshold_yocto, denied_recipients, created_at)
           VALUES ('orphan', 'missing-agent', 1, '10', '2', '[]', '2026-01-01T00:00:00.000Z')`,
        )
        .run();
    }, /FOREIGN KEY constraint failed/);
  });
});

test("transaction decisions and their audit records persist", () => {
  withDatabase((database) => {
    const { agent, policy } = database.createAgent("Persistent agent", "");
    const transaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "1",
      asset: "NEAR",
      reason: "Test persistence",
    };
    const result = evaluateTransaction(transaction, agent, {
      version: policy.version,
      maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policy.approvalThresholdYocto,
      deniedRecipients: policy.deniedRecipients,
    });
    const saved = database.createEvaluation({
      agentId: agent.id,
      transaction,
      result,
      policy,
    });
    const record = database.getTransaction(saved.transactionId);
    const audit = database.listAudit().find((event) => event.entityId === saved.transactionId);

    assert.equal(record?.decision.decision, "ALLOW");
    assert.equal(record?.decision.policyVersion, "1");
    assert.deepEqual(record?.decision.policySnapshot.deniedRecipients, []);
    assert.equal(audit?.eventType, "transaction.evaluated");
    assert.equal(audit?.details.policyVersion, "1");
  });
});

test("evaluation persistence rolls back all records if an audit insert fails", () => {
  withDatabase((database) => {
    const { agent, policy } = database.createAgent("Atomic agent", "");
    const transaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "1",
      asset: "NEAR",
      reason: "Atomicity test",
    };
    const result = evaluateTransaction(transaction, agent, {
      version: policy.version,
      maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policy.approvalThresholdYocto,
      deniedRecipients: policy.deniedRecipients,
    });
    database.connection.exec(`
      CREATE TRIGGER reject_evaluation_audit
      BEFORE INSERT ON audit_logs
      WHEN NEW.event_type = 'transaction.evaluated'
      BEGIN
        SELECT RAISE(ABORT, 'test failure');
      END;
    `);

    assert.throws(() =>
      database.createEvaluation({ agentId: agent.id, transaction, result, policy }),
    );
    const countRows = (table: "transactions" | "decisions" | "approvals") =>
      (
        database.connection.prepare(`SELECT count(*) AS count FROM ${table}`).get() as {
          count: number;
        }
      ).count;
    assert.equal(countRows("transactions"), 0);
    assert.equal(countRows("decisions"), 0);
    assert.equal(countRows("approvals"), 0);
  });
});

test("policy revisions are retained and audit records are append-only", () => {
  withDatabase((database) => {
    const { agent } = database.createAgent("Versioned agent", "");
    const updated = database.updatePolicy(agent.id, {
      maxTransactionAmountYocto: "20",
      approvalThresholdYocto: "5",
      deniedRecipients: [],
    });
    const rows = database.connection
      .prepare("SELECT version FROM policies WHERE agent_id = ? ORDER BY version")
      .all(agent.id) as Array<{ version: number }>;

    assert.equal(updated?.version, "2");
    assert.deepEqual(rows.map((row) => row.version), [1, 2]);
    assert.throws(
      () => database.connection.prepare("UPDATE audit_logs SET event_type = 'changed'").run(),
      /audit logs are append-only/,
    );
    assert.throws(
      () => database.connection.prepare("DELETE FROM audit_logs").run(),
      /audit logs are append-only/,
    );
  });
});
