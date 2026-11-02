import assert from "node:assert/strict";
import BetterSqlite3 from "better-sqlite3";
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

function createAllowEvaluation(database: SentraDatabase) {
  const { agent, policy } = database.createAgent("Authorization test agent", "");
  const transaction = {
    agentId: agent.id,
    network: "near-testnet",
    transactionType: "native_transfer",
    recipient: "recipient.testnet",
    amountYocto: "1",
    asset: "NEAR",
    reason: "Authorization intent test",
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
  return { agent, policy, transaction, evaluation };
}

function createAuthorizationIntent(
  database: SentraDatabase,
  values: ReturnType<typeof createAllowEvaluation>,
  token = "a".repeat(64),
) {
  database.setAgentAuthorizedNearAccount(values.agent.id, "authorized.testnet");
  return database.createAuthorizationIntent({
    transactionId: values.evaluation.transactionId,
    decisionId: values.evaluation.decisionId,
    approvalId: null,
    tokenHash: token,
    policyId: values.policy.id,
    policyVersion: values.policy.version,
    authorizedWalletAccountId: "authorized.testnet",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
}

function createApprovedWarnEvaluation(database: SentraDatabase, agentId: string) {
  const agent = database.getAgent(agentId)!;
  const policy = database.getCurrentPolicy(agentId)!;
  const transaction = {
    agentId,
    network: "near-testnet",
    transactionType: "native_transfer",
    recipient: "recipient.testnet",
    amountYocto: (2n * 10n ** 24n).toString(),
    asset: "NEAR",
    reason: "Approved WARN test",
  };
  const result = evaluateTransaction(transaction, agent, {
    version: policy.version,
    maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
    approvalThresholdYocto: policy.approvalThresholdYocto,
    deniedRecipients: policy.deniedRecipients,
  });
  const evaluation = database.createEvaluation({ agentId, transaction, result, policy });
  const approval = database.reviewApproval(evaluation.approval!.id, "approved", "Local reviewer")!;
  return { agent, policy, transaction, evaluation, approval };
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
      "authorization_intents",
      "chain_verifications",
      "decisions",
      "policies",
      "threat_simulations",
      "transactions",
    ]);
    assert.equal(database.connection.pragma("foreign_keys", { simple: true }), 1);
    assert.equal(database.connection.pragma("user_version", { simple: true }), 3);
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
    assert.equal(reopened.connection.pragma("user_version", { simple: true }), 3);
  } finally {
    reopened.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("migrates the existing schema additively and preserves existing records", () => {
  const directory = mkdtempSync(join(tmpdir(), "sentra-db-migration-test-"));
  const filename = join(directory, "legacy.sqlite");
  const legacy = new SentraDatabase(filename);
  const { agent, evaluation, policy } = createAllowEvaluation(legacy);
  const before = legacy.getTransaction(evaluation.transactionId);
  const auditBefore = legacy.listAudit().length;
  legacy.close();

  const legacyConnection = new BetterSqlite3(filename);
  legacyConnection.pragma("foreign_keys = OFF");
  legacyConnection.exec(`
    DROP TRIGGER authorization_intents_validate_insert;
    DROP TRIGGER authorization_intents_validate_transition;
    DROP TRIGGER authorization_intents_protect_snapshot;
    DROP TRIGGER authorization_intents_validate_initial_state;
    DROP TRIGGER authorization_intents_validate_wallet_snapshot;
    DROP TRIGGER authorization_intents_validate_current_authorization;
    DROP TRIGGER authorization_intents_protect_claim;
    DROP TRIGGER agents_validate_near_account_insert;
    DROP TRIGGER agents_validate_near_account_update;
    DROP TRIGGER agents_invalidate_outstanding_intents;
    DROP TRIGGER policies_invalidate_outstanding_intents;
    DROP TABLE chain_verifications;
    DROP TABLE authorization_intents;
    DROP INDEX idx_agents_authorized_near_account;
    ALTER TABLE agents DROP COLUMN authorized_near_account_id;
  `);
  legacyConnection.pragma("user_version = 0");
  legacyConnection.close();

  const migrated = new SentraDatabase(filename);
  try {
    assert.equal(migrated.connection.pragma("user_version", { simple: true }), 3);
    assert.equal(migrated.getAgent(agent.id)?.authorizedNearAccountId, null);
    assert.deepEqual(migrated.getTransaction(evaluation.transactionId), before);
    assert.equal(migrated.getCurrentPolicy(agent.id)?.id, policy.id);
    assert.equal(migrated.listAudit().length, auditBefore);
    assert.ok(
      migrated.connection
        .prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'chain_verifications'")
        .get(),
    );
  } finally {
    migrated.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("migrates version 2 to version 3 while preserving authorization intents", () => {
  const directory = mkdtempSync(join(tmpdir(), "sentra-db-v2-v3-migration-test-"));
  const filename = join(directory, "version-2.sqlite");
  const version2 = new SentraDatabase(filename);
  const allowValues = createAllowEvaluation(version2);
  const issuedIntent = createAuthorizationIntent(version2, allowValues, "e".repeat(64));
  const warnValues = createApprovedWarnEvaluation(version2, allowValues.agent.id);
  const indeterminateIntent = version2.createAuthorizationIntent({
    transactionId: warnValues.evaluation.transactionId,
    decisionId: warnValues.evaluation.decisionId,
    approvalId: warnValues.approval.id,
    tokenHash: "f".repeat(64),
    policyId: warnValues.policy.id,
    policyVersion: warnValues.policy.version,
    authorizedWalletAccountId: "authorized.testnet",
    expiresAt: new Date(Date.now() + 60_000).toISOString(),
  });
  const transactionHash = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZT";
  assert.ok(
    version2.startAuthorizationIntentVerification(
      indeterminateIntent.id,
      transactionHash,
      "authorized.testnet",
    ),
  );
  version2.completeAuthorizationIntentVerification({
    authorizationIntentId: indeterminateIntent.id,
    transactionHash,
    status: "unverified",
    reason: "RPC timeout",
    observedSignerAccountId: null,
    observedReceiverAccountId: null,
    observedAmountYocto: null,
    verifiedAt: new Date().toISOString(),
  });
  const intentsBeforeMigration = version2.connection
    .prepare("SELECT * FROM authorization_intents ORDER BY id")
    .all();
  assert.deepEqual(
    intentsBeforeMigration.map((row) => (row as { state: string }).state).sort(),
    ["indeterminate", "issued"],
  );
  version2.close();

  const legacyConnection = new BetterSqlite3(filename);
  legacyConnection.exec(`
    DROP TRIGGER authorization_intents_validate_insert;
    CREATE TRIGGER authorization_intents_validate_insert
      BEFORE INSERT ON authorization_intents
      BEGIN
        SELECT CASE WHEN NOT EXISTS (
          SELECT 1
          FROM transactions t
          JOIN decisions d ON d.id = NEW.decision_id AND d.transaction_id = t.id
          JOIN policies p ON p.id = NEW.policy_id
            AND p.agent_id = t.agent_id
            AND CAST(p.version AS TEXT) = NEW.policy_version
          JOIN agents a ON a.id = t.agent_id
            AND a.authorized_near_account_id = NEW.authorized_wallet_account_id
          WHERE t.id = NEW.transaction_id
            AND d.policy_id = NEW.policy_id
            AND d.policy_version = NEW.policy_version
            AND d.decision IN ('ALLOW', 'WARN')
            AND a.enabled = 1
            AND p.version = (
              SELECT MAX(current_policy.version)
              FROM policies current_policy
              WHERE current_policy.agent_id = p.agent_id
            )
            AND (
              (d.decision = 'ALLOW' AND NEW.approval_id IS NULL)
              OR (
                d.decision = 'WARN'
                AND EXISTS (
                  SELECT 1 FROM approvals ap
                  WHERE ap.id = NEW.approval_id
                    AND ap.decision_id = d.id
                    AND ap.status = 'approved'
                )
              )
            )
        ) THEN RAISE(ABORT, 'authorization intent does not match eligible records') END;
      END;
  `);
  legacyConnection.pragma("user_version = 2");
  legacyConnection.close();

  const migrated = new SentraDatabase(filename);
  try {
    assert.equal(migrated.connection.pragma("user_version", { simple: true }), 3);
    assert.deepEqual(
      migrated.connection
        .prepare("SELECT * FROM authorization_intents ORDER BY id")
        .all(),
      intentsBeforeMigration,
    );
    assert.equal(migrated.getAuthorizationIntent(issuedIntent.id)?.state, "issued");
    assert.equal(
      migrated.getAuthorizationIntent(indeterminateIntent.id)?.state,
      "indeterminate",
    );
    assert.ok(
      migrated.connection
        .prepare(
          "SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = 'authorization_intents_validate_insert'",
        )
        .get(),
    );

    migrated.connection
      .prepare("UPDATE transactions SET status = 'ALLOW' WHERE id = ?")
      .run(warnValues.evaluation.transactionId);
    assert.throws(
      () =>
        migrated.connection
          .prepare(
            `INSERT INTO authorization_intents
             (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
              policy_version, authorized_wallet_account_id, expires_at, created_at, state)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued')`,
          )
          .run(
            "invalid-v3-migration-intent",
            warnValues.evaluation.transactionId,
            warnValues.evaluation.decisionId,
            warnValues.approval.id,
            "1".repeat(64),
            warnValues.policy.id,
            warnValues.policy.version,
            "authorized.testnet",
            new Date(Date.now() + 60_000).toISOString(),
            new Date().toISOString(),
          ),
      /authorization intent does not match eligible records/,
    );
  } finally {
    migrated.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("migration is repeatable and leaves existing schema version and rows unchanged", () => {
  const directory = mkdtempSync(join(tmpdir(), "sentra-db-migration-repeat-test-"));
  const filename = join(directory, "repeat.sqlite");
  const first = new SentraDatabase(filename);
  const { agent } = first.createAgent("Repeatable migration agent", "");
  first.close();

  const second = new SentraDatabase(filename);
  try {
    assert.equal(second.connection.pragma("user_version", { simple: true }), 3);
    assert.equal(second.getAgent(agent.id)?.id, agent.id);
    assert.equal(
      (
        second.connection
          .prepare("SELECT count(*) AS count FROM authorization_intents")
          .get() as { count: number }
      ).count,
      0,
    );
  } finally {
    second.close();
    rmSync(directory, { recursive: true, force: true });
  }
});

test("wallet bindings remain unset by default and are unique when assigned", () => {
  withDatabase((database) => {
    const first = database.createAgent("First agent", "").agent;
    const second = database.createAgent("Second agent", "").agent;
    assert.equal(first.authorizedNearAccountId, null);
    assert.equal(second.authorizedNearAccountId, null);

    assert.equal(
      database.setAgentAuthorizedNearAccount(first.id, "authorized.testnet")
        ?.authorizedNearAccountId,
      "authorized.testnet",
    );
    assert.throws(
      () => database.setAgentAuthorizedNearAccount(second.id, "authorized.testnet"),
      /UNIQUE constraint failed/,
    );
    assert.throws(
      () => database.setAgentAuthorizedNearAccount(second.id, "Bad Account"),
      /account ID is invalid/,
    );
  });
});

test("SQLite rejects malformed NEAR accounts in direct wallet-binding and intent writes", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(values.agent.id, "authorized.testnet");

    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE agents SET authorized_near_account_id = '..' WHERE id = ?")
          .run(values.agent.id),
      /invalid authorized NEAR account ID/,
    );
    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE agents SET authorized_near_account_id = 'bad..account' WHERE id = ?")
          .run(values.agent.id),
      /invalid authorized NEAR account ID/,
    );

    database.connection.exec("DROP TRIGGER authorization_intents_validate_insert");
    assert.throws(
      () =>
        database.connection
          .prepare(
            `INSERT INTO authorization_intents
              (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
               policy_version, authorized_wallet_account_id, expires_at, created_at, state)
             VALUES ('malformed-wallet', ?, ?, NULL, ?, ?, ?, '..', ?, ?, 'issued')`,
          )
          .run(
            values.evaluation.transactionId,
            values.evaluation.decisionId,
            "f".repeat(64),
            values.policy.id,
            values.policy.version,
            new Date(Date.now() + 60_000).toISOString(),
            new Date().toISOString(),
          ),
      /invalid authorization wallet account ID/,
    );
  });
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

test("authorization intents persist hashed tokens, snapshots, expiry, and one-time state", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const rawToken = "raw-one-time-token";
    const tokenHash = "b".repeat(64);
    const intent = createAuthorizationIntent(database, values, tokenHash);
    const byToken = database.getAuthorizationIntentByTokenHash(
      values.evaluation.transactionId,
      tokenHash,
    );
    const storedToken = database.connection
      .prepare("SELECT token_hash FROM authorization_intents WHERE id = ?")
      .get(intent.id) as { token_hash: string };

    assert.equal(intent.state, "issued");
    assert.equal(intent.transactionId, values.evaluation.transactionId);
    assert.equal(intent.decisionId, values.evaluation.decisionId);
    assert.equal(intent.policyId, values.policy.id);
    assert.equal(intent.policyVersion, values.policy.version);
    assert.equal(intent.authorizedWalletAccountId, "authorized.testnet");
    assert.ok(Date.parse(intent.expiresAt) > Date.now());
    assert.equal(byToken?.id, intent.id);
    assert.equal(storedToken.token_hash, tokenHash);
    assert.notEqual(storedToken.token_hash, rawToken);
    assert.equal(intent.transactionHash, null);
    assert.equal(intent.claimedSignerAccountId, null);
    assert.equal(intent.consumedAt, null);
  });
});

test("policy, disable, and wallet-binding changes invalidate outstanding intents", () => {
  const createIndeterminateIntent = (
    database: SentraDatabase,
    values: ReturnType<typeof createAllowEvaluation>,
    token: string,
  ) => {
    const intent = createAuthorizationIntent(database, values, token);
    const hash = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS";
    assert.ok(
      database.startAuthorizationIntentVerification(
        intent.id,
        hash,
        "authorized.testnet",
      ),
    );
    database.completeAuthorizationIntentVerification({
      authorizationIntentId: intent.id,
      transactionHash: hash,
      status: "unverified",
      reason: "RPC timeout",
      observedSignerAccountId: null,
      observedReceiverAccountId: null,
      observedAmountYocto: null,
      verifiedAt: new Date().toISOString(),
    });
    return intent.id;
  };

  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const issuedId = createAuthorizationIntent(database, values).id;
    const indeterminateId = createIndeterminateIntent(database, values, "b".repeat(64));
    const updated = database.updatePolicy(values.agent.id, {
      maxTransactionAmountYocto: values.policy.maxTransactionAmountYocto,
      approvalThresholdYocto: values.policy.approvalThresholdYocto,
      deniedRecipients: ["other.testnet"],
    });

    assert.equal(updated?.version, "2");
    for (const id of [issuedId, indeterminateId]) {
      assert.equal(database.getAuthorizationIntent(id)?.state, "stale");
      assert.ok(database.getAuthorizationIntent(id)?.consumedAt);
      assert.equal(
        database.startAuthorizationIntentVerification(
          id,
          "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS",
          "authorized.testnet",
        ),
        undefined,
      );
    }
    assert.equal(
      database
        .listAudit()
        .filter((entry) => entry.eventType === "authorization_intent.stale").length,
      2,
    );
  });

  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const issuedId = createAuthorizationIntent(database, values).id;
    const indeterminateId = createIndeterminateIntent(database, values, "c".repeat(64));
    database.setAgentEnabled(values.agent.id, false);

    for (const id of [issuedId, indeterminateId]) {
      assert.equal(database.getAuthorizationIntent(id)?.state, "stale");
      assert.ok(database.getAuthorizationIntent(id)?.consumedAt);
    }
    assert.equal(
      database
        .listAudit()
        .filter((entry) => entry.eventType === "authorization_intent.stale").length,
      2,
    );
  });

  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const issuedId = createAuthorizationIntent(database, values).id;
    const indeterminateId = createIndeterminateIntent(database, values, "d".repeat(64));
    database.setAgentAuthorizedNearAccount(values.agent.id, "replacement.testnet");

    for (const id of [issuedId, indeterminateId]) {
      assert.equal(database.getAuthorizationIntent(id)?.state, "stale");
      assert.ok(database.getAuthorizationIntent(id)?.consumedAt);
    }
    assert.equal(
      database
        .listAudit()
        .filter((entry) => entry.eventType === "authorization_intent.stale").length,
      2,
    );
  });
});

test("authorization invalidation rolls back with agent and policy changes if audit fails", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const intent = createAuthorizationIntent(database, values);
    database.connection.exec(`
      CREATE TRIGGER reject_intent_stale_audit
      BEFORE INSERT ON audit_logs
      WHEN NEW.event_type = 'authorization_intent.stale'
      BEGIN
        SELECT RAISE(ABORT, 'test invalidation audit failure');
      END;
    `);

    assert.throws(
      () => database.setAgentEnabled(values.agent.id, false),
      /test invalidation audit failure/,
    );
    assert.equal(database.getAgent(values.agent.id)?.enabled, true);
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "issued");

    assert.throws(
      () =>
        database.updatePolicy(values.agent.id, {
          maxTransactionAmountYocto: values.policy.maxTransactionAmountYocto,
          approvalThresholdYocto: values.policy.approvalThresholdYocto,
          deniedRecipients: ["other.testnet"],
        }),
      /test invalidation audit failure/,
    );
    assert.equal(database.getCurrentPolicy(values.agent.id)?.version, "1");
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "issued");
  });
});

test("post-RPC completion rechecks current authorization before marking intent verified", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const intent = createAuthorizationIntent(database, values);
    const hash = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS";
    assert.ok(
      database.startAuthorizationIntentVerification(
        intent.id,
        hash,
        "authorized.testnet",
      ),
    );
    database.updatePolicy(values.agent.id, {
      maxTransactionAmountYocto: values.policy.maxTransactionAmountYocto,
      approvalThresholdYocto: values.policy.approvalThresholdYocto,
      deniedRecipients: ["other.testnet"],
    });

    const completed = database.completeAuthorizationIntentVerification({
      authorizationIntentId: intent.id,
      transactionHash: hash,
      status: "verified",
      reason: "Finalized transfer verified",
      observedSignerAccountId: "authorized.testnet",
      observedReceiverAccountId: "recipient.testnet",
      observedAmountYocto: "1",
      verifiedAt: new Date().toISOString(),
    });

    assert.equal(completed.status, "verified");
    assert.equal(completed.authorizationIntentState, "stale");
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "stale");
    assert.ok(database.getAuthorizationIntent(intent.id)?.consumedAt);
  });
});

test("WARN intent requires its linked approved human approval", () => {
  withDatabase((database) => {
    const { agent, policy } = database.createAgent("WARN authorization agent", "");
    database.setAgentAuthorizedNearAccount(agent.id, "authorized.testnet");
    const transaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: (2n * 10n ** 24n).toString(),
      asset: "NEAR",
      reason: "Approval required",
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
    const approval = database.getApproval(evaluation.approval!.id)!;
    const createIntent = (approvalId: string | null, tokenHash: string) =>
      database.createAuthorizationIntent({
        transactionId: evaluation.transactionId,
        decisionId: evaluation.decisionId,
        approvalId,
        tokenHash,
        policyId: policy.id,
        policyVersion: policy.version,
        authorizedWalletAccountId: "authorized.testnet",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

    assert.equal(result.decision, "WARN");
    assert.throws(
      () => createIntent(null, "f".repeat(64)),
      /does not match current eligible records/,
    );
    database.reviewApproval(approval.id, "approved", "Local reviewer");
    const intent = createIntent(approval.id, "e".repeat(64));
    assert.equal(intent.approvalId, approval.id);
    assert.equal(intent.state, "issued");
  });
});

test("database intent creation rejects mismatched WARN approval relationships", () => {
  withDatabase((database) => {
    const firstAgent = database.createAgent("First WARN agent", "").agent;
    const secondAgent = database.createAgent("Second WARN agent", "").agent;
    database.setAgentAuthorizedNearAccount(firstAgent.id, "first.testnet");
    database.setAgentAuthorizedNearAccount(secondAgent.id, "second.testnet");
    const first = createApprovedWarnEvaluation(database, firstAgent.id);
    const sameAgentDifferentDecision = createApprovedWarnEvaluation(database, firstAgent.id);
    const otherAgentApproval = createApprovedWarnEvaluation(database, secondAgent.id);

    const intentInput = {
      transactionId: first.evaluation.transactionId,
      decisionId: first.evaluation.decisionId,
      approvalId: first.approval.id,
      tokenHash: "1".repeat(64),
      policyId: first.policy.id,
      policyVersion: first.policy.version,
      authorizedWalletAccountId: "first.testnet",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    assert.throws(
      () => database.createAuthorizationIntent({ ...intentInput, approvalId: null }),
      /does not match current eligible records/,
    );
    assert.throws(
      () =>
        database.createAuthorizationIntent({
          ...intentInput,
          approvalId: sameAgentDifferentDecision.approval.id,
        }),
      /does not match current eligible records/,
    );
    assert.throws(
      () =>
        database.createAuthorizationIntent({
          ...intentInput,
          approvalId: otherAgentApproval.approval.id,
        }),
      /does not match current eligible records/,
    );
    assert.throws(
      () =>
        database.createAuthorizationIntent({
          ...intentInput,
          policyVersion: "99",
        }),
      /does not match current eligible records/,
    );
  });
});

test("database intent creation rejects changed agent, binding, or policy before insertion", () => {
  withDatabase((database) => {
    const disabledValues = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(disabledValues.agent.id, "authorized.testnet");
    const baseInput = {
      transactionId: disabledValues.evaluation.transactionId,
      decisionId: disabledValues.evaluation.decisionId,
      approvalId: null,
      tokenHash: "2".repeat(64),
      policyId: disabledValues.policy.id,
      policyVersion: disabledValues.policy.version,
      authorizedWalletAccountId: "authorized.testnet",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };

    database.setAgentEnabled(disabledValues.agent.id, false);
    assert.throws(
      () => database.createAuthorizationIntent(baseInput),
      /does not match current eligible records/,
    );
    database.setAgentEnabled(disabledValues.agent.id, true);

    database.setAgentAuthorizedNearAccount(disabledValues.agent.id, "replacement.testnet");
    assert.throws(
      () => database.createAuthorizationIntent(baseInput),
      /does not match current eligible records/,
    );

    const policyValues = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(policyValues.agent.id, "policy.testnet");
    const stalePolicyInput = {
      transactionId: policyValues.evaluation.transactionId,
      decisionId: policyValues.evaluation.decisionId,
      approvalId: null,
      tokenHash: "3".repeat(64),
      policyId: policyValues.policy.id,
      policyVersion: policyValues.policy.version,
      authorizedWalletAccountId: "policy.testnet",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    database.updatePolicy(policyValues.agent.id, {
      maxTransactionAmountYocto: policyValues.policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policyValues.policy.approvalThresholdYocto,
      deniedRecipients: ["other.testnet"],
    });

    assert.throws(
      () => database.createAuthorizationIntent(stalePolicyInput),
      /does not match current eligible records/,
    );
  });
});

test("direct SQL intent insertion rejects invalid authorization relationships", () => {
  withDatabase((database) => {
    const first = createAllowEvaluation(database);
    const second = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(first.agent.id, "first.testnet");
    database.setAgentAuthorizedNearAccount(second.agent.id, "second.testnet");
    const statement = database.connection.prepare(
      `INSERT INTO authorization_intents
        (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
         policy_version, authorized_wallet_account_id, expires_at, created_at, state)
       VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, ?, 'issued')`,
    );
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const createdAt = new Date().toISOString();

    assert.throws(
      () =>
        statement.run(
          "wrong-agent-policy",
          first.evaluation.transactionId,
          first.evaluation.decisionId,
          "4".repeat(64),
          second.policy.id,
          second.policy.version,
          "first.testnet",
          expiresAt,
          createdAt,
        ),
      /authorization intent does not match eligible records/,
    );

    const warn = createApprovedWarnEvaluation(database, first.agent.id);
    const mismatchedApproval = createApprovedWarnEvaluation(database, second.agent.id);
    assert.throws(
      () =>
        database.connection
          .prepare(
            `INSERT INTO authorization_intents
              (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
               policy_version, authorized_wallet_account_id, expires_at, created_at, state)
             VALUES ('wrong-warn-approval', ?, ?, NULL, ?, ?, ?, 'first.testnet', ?, ?, 'issued')`,
          )
          .run(
            warn.evaluation.transactionId,
            warn.evaluation.decisionId,
            "5".repeat(64),
            warn.policy.id,
            warn.policy.version,
            expiresAt,
            createdAt,
          ),
      /authorization intent does not match eligible records/,
    );
    assert.throws(
      () =>
        database.connection
          .prepare(
            `INSERT INTO authorization_intents
              (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
               policy_version, authorized_wallet_account_id, expires_at, created_at, state)
             VALUES ('wrong-warn-approval', ?, ?, ?, ?, ?, ?, 'first.testnet', ?, ?, 'issued')`,
          )
          .run(
            warn.evaluation.transactionId,
            warn.evaluation.decisionId,
            mismatchedApproval.approval.id,
            "6".repeat(64),
            warn.policy.id,
            warn.policy.version,
            expiresAt,
            createdAt,
          ),
      /authorization intent does not match eligible records/,
    );
  });
});

test("intent state transitions bind one signer and hash and persist verification", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const intent = createAuthorizationIntent(database, values);
    const hash = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS";

    assert.equal(
      database.startAuthorizationIntentVerification(intent.id, hash, "other.testnet"),
      undefined,
    );
    const verifying = database.startAuthorizationIntentVerification(
      intent.id,
      hash,
      "authorized.testnet",
    );
    assert.equal(verifying?.state, "verifying");
    assert.equal(verifying?.transactionHash, hash);
    assert.equal(verifying?.claimedSignerAccountId, "authorized.testnet");
    assert.throws(
      () =>
        database.connection
          .prepare(
            "UPDATE authorization_intents SET transaction_hash = ?, claimed_signer_account_id = ? WHERE id = ?",
          )
          .run("6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZT", "other.testnet", intent.id),
      /authorization intent claim is immutable/,
    );

    const firstResult = database.completeAuthorizationIntentVerification({
      authorizationIntentId: intent.id,
      transactionHash: hash,
      status: "unverified",
      reason: "RPC timeout",
      observedSignerAccountId: null,
      observedReceiverAccountId: null,
      observedAmountYocto: null,
      verifiedAt: new Date().toISOString(),
    });
    assert.equal(firstResult.status, "unverified");
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "indeterminate");
    assert.equal(database.getAuthorizationIntent(intent.id)?.consumedAt, null);

    assert.equal(
      database.startAuthorizationIntentVerification(
        intent.id,
        "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZT",
        "authorized.testnet",
      ),
      undefined,
    );
    assert.ok(
      database.startAuthorizationIntentVerification(intent.id, hash, "authorized.testnet"),
    );

    const finalResult = database.completeAuthorizationIntentVerification({
      authorizationIntentId: intent.id,
      transactionHash: hash,
      status: "verified",
      reason: "Transfer verified",
      observedSignerAccountId: "authorized.testnet",
      observedReceiverAccountId: "recipient.testnet",
      observedAmountYocto: "1",
      verifiedAt: new Date().toISOString(),
    });
    const persisted = database.getChainVerification(intent.id);
    const finalIntent = database.getAuthorizationIntent(intent.id);
    const audit = database.listAudit().filter((entry) => entry.entityId === intent.id);

    assert.equal(finalResult.status, "verified");
    assert.equal(finalResult.authorizationIntentState, "verified");
    assert.equal(persisted?.transactionHash, hash);
    assert.equal(persisted?.observedSignerAccountId, "authorized.testnet");
    assert.equal(persisted?.observedReceiverAccountId, "recipient.testnet");
    assert.equal(persisted?.observedAmountYocto, "1");
    assert.ok(persisted?.createdAt);
    assert.ok(persisted?.verifiedAt);
    assert.equal(finalIntent?.state, "verified");
    assert.ok(finalIntent?.consumedAt);
    assert.equal(
      audit.filter((entry) => entry.eventType === "chain_verification.completed").length,
      2,
    );
    const verificationAttempts = audit.filter(
      (entry) => entry.eventType === "chain_verification.completed",
    );
    assert.ok(
      verificationAttempts.some(
        (entry) =>
          entry.details.status === "verified" &&
          entry.details.observedReceiverAccountId === "recipient.testnet" &&
          entry.details.observedAmountYocto === "1",
      ),
    );
    assert.ok(
      verificationAttempts.some(
        (entry) =>
          entry.details.status === "unverified" &&
          entry.details.reason === "RPC timeout",
      ),
    );
  });
});

test("expired and stale intent transitions are audited and consumed", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const expiredIntent = createAuthorizationIntent(database, values);
    const staleIntent = createAuthorizationIntent(database, values, "c".repeat(64));

    const expired = database.invalidateAuthorizationIntent(
      expiredIntent.id,
      "expired",
      "Intent expired",
    );
    const stale = database.invalidateAuthorizationIntent(staleIntent.id, "stale", "Policy changed");
    const events = database.listAudit().filter((event) => event.entityType === "authorization_intent");

    assert.equal(expired?.state, "expired");
    assert.ok(expired?.consumedAt);
    assert.equal(stale?.state, "stale");
    assert.ok(stale?.consumedAt);
    assert.ok(events.some((event) => event.eventType === "authorization_intent.expired"));
    assert.ok(events.some((event) => event.eventType === "authorization_intent.stale"));
  });
});

test("intent foreign keys and uniqueness constraints reject invalid records", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(values.agent.id, "authorized.testnet");
    const input = {
      transactionId: values.evaluation.transactionId,
      decisionId: values.evaluation.decisionId,
      approvalId: null,
      tokenHash: "d".repeat(64),
      policyId: values.policy.id,
      policyVersion: values.policy.version,
      authorizedWalletAccountId: "authorized.testnet",
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    };
    database.createAuthorizationIntent(input);
    assert.throws(
      () => database.createAuthorizationIntent({ ...input, tokenHash: "d".repeat(64) }),
      /UNIQUE constraint failed/,
    );
    database.connection.exec("DROP TRIGGER authorization_intents_validate_insert");
    assert.throws(
      () =>
        database.connection
          .prepare(
            `INSERT INTO authorization_intents
              (id, transaction_id, decision_id, token_hash, policy_id, policy_version,
               authorized_wallet_account_id, expires_at, created_at, state)
             VALUES ('orphan', 'missing', 'missing', ?, 'missing', '1',
                     'authorized.testnet', ?, ?, 'issued')`,
          )
          .run("e".repeat(64), new Date(Date.now() + 60_000).toISOString(), new Date().toISOString()),
      /FOREIGN KEY constraint failed/,
    );
  });
});

test("intent initial states, transitions, and immutable snapshots are enforced", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    const intent = createAuthorizationIntent(database, values);

    assert.throws(
      () =>
        database.connection
          .prepare(
            `INSERT INTO authorization_intents
              (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
               policy_version, authorized_wallet_account_id, expires_at, created_at, state)
             VALUES ('wrong-initial-state', ?, ?, NULL, ?, ?, ?, 'authorized.testnet',
                     ?, ?, 'verifying')`,
          )
          .run(
            values.evaluation.transactionId,
            values.evaluation.decisionId,
            "e".repeat(64),
            values.policy.id,
            values.policy.version,
            new Date(Date.now() + 60_000).toISOString(),
            new Date().toISOString(),
          ),
      /new authorization intents must start in issued state/,
    );
    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE authorization_intents SET state = 'issued' WHERE id = ?")
          .run(intent.id),
      /invalid authorization intent state transition/,
    );
    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE authorization_intents SET policy_version = '99' WHERE id = ?")
          .run(intent.id),
      /authorization intent snapshot is immutable/,
    );
    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE authorization_intents SET authorized_wallet_account_id = 'other.testnet' WHERE id = ?")
          .run(intent.id),
      /authorization intent snapshot is immutable/,
    );
  });
});

test("intent creation and verification persistence roll back with failed audit writes", () => {
  withDatabase((database) => {
    const values = createAllowEvaluation(database);
    database.setAgentAuthorizedNearAccount(values.agent.id, "authorized.testnet");
    database.connection.exec(`
      CREATE TRIGGER reject_intent_audit
      BEFORE INSERT ON audit_logs
      WHEN NEW.event_type = 'authorization_intent.issued'
      BEGIN
        SELECT RAISE(ABORT, 'test failure');
      END;
    `);

    assert.throws(() => createAuthorizationIntent(database, values), /test failure/);
    assert.equal(
      (
        database.connection
          .prepare("SELECT count(*) AS count FROM authorization_intents")
          .get() as { count: number }
      ).count,
      0,
    );
    database.connection.exec("DROP TRIGGER reject_intent_audit");

    const intent = createAuthorizationIntent(database, values);
    const hash = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS";
    assert.ok(
      database.startAuthorizationIntentVerification(intent.id, hash, "authorized.testnet"),
    );
    assert.throws(
      () =>
        database.connection
          .prepare("UPDATE authorization_intents SET state = 'issued' WHERE id = ?")
          .run(intent.id),
      /invalid authorization intent state transition/,
    );
    database.connection.exec(`
      CREATE TRIGGER reject_verification_audit
      BEFORE INSERT ON audit_logs
      WHEN NEW.event_type = 'chain_verification.completed'
      BEGIN
        SELECT RAISE(ABORT, 'test failure');
      END;
    `);

    assert.throws(
      () =>
        database.completeAuthorizationIntentVerification({
          authorizationIntentId: intent.id,
          transactionHash: hash,
          status: "verified",
          reason: "Transfer verified",
          observedSignerAccountId: "authorized.testnet",
          observedReceiverAccountId: "recipient.testnet",
          observedAmountYocto: "1",
          verifiedAt: new Date().toISOString(),
        }),
      /test failure/,
    );
    assert.equal(database.getAuthorizationIntent(intent.id)?.state, "verifying");
    assert.equal(database.getChainVerification(intent.id), undefined);
  });
});
