import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { evaluateTransaction } from "../engine/policyEngine.js";
import { SentraDatabase } from "../database/database.js";
import {
  TransactionAuthorizationError,
  TransactionAuthorizationService,
} from "./transactionAuthorizationService.js";

const NEAR = 10n ** 24n;

interface Fixture {
  database: SentraDatabase;
  service: TransactionAuthorizationService;
  agentId: string;
  transactionId: string;
  decisionId: string;
  approvalId: string | null;
  close(): void;
}

function createFixture(options: {
  amountYocto?: string;
  network?: string;
  transactionType?: string;
  asset?: string;
  enabled?: boolean;
  bindWallet?: boolean;
  approveWarn?: boolean;
} = {}): Fixture {
  const directory = mkdtempSync(join(tmpdir(), "sentra-prepare-test-"));
  const database = new SentraDatabase(join(directory, "test.sqlite"));
  const created = database.createAgent("Preparation service agent", "");
  const agentId = created.agent.id;
  if (options.bindWallet !== false) {
    database.setAgentAuthorizedNearAccount(agentId, "authorized.testnet");
  }
  if (options.enabled === false) {
    database.setAgentEnabled(agentId, false);
  }

  const transaction = {
    agentId,
    network: options.network ?? "near-testnet",
    transactionType: options.transactionType ?? "native_transfer",
    recipient: "recipient.testnet",
    amountYocto: options.amountYocto ?? "1",
    asset: options.asset ?? "NEAR",
    reason: "Preparation test",
  };
  const policy = database.getCurrentPolicy(agentId)!;
  const agent = database.getAgent(agentId)!;
  const policyForEvaluation = {
    version: policy.version,
    maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
    approvalThresholdYocto: policy.approvalThresholdYocto,
    deniedRecipients: policy.deniedRecipients,
  };
  const evaluated = evaluateTransaction(transaction, agent, policyForEvaluation);
  const saved = database.createEvaluation({
    agentId,
    transaction,
    result: evaluated,
    policy,
  });
  let approvalId: string | null = saved.approval?.id ?? null;
  if (options.approveWarn && approvalId) {
    database.reviewApproval(approvalId, "approved", "Local reviewer");
  }

  return {
    database,
    service: new TransactionAuthorizationService(database),
    agentId,
    transactionId: saved.transactionId,
    decisionId: saved.decisionId,
    approvalId,
    close() {
      database.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

function withFixture(
  run: (fixture: Fixture) => void | Promise<void>,
  options: Parameters<typeof createFixture>[0] = {},
): Promise<void> {
  const fixture = createFixture(options);
  return Promise.resolve(run(fixture)).finally(fixture.close);
}

function assertAuthorizationError(
  action: () => unknown,
  code: string,
): void {
  assert.throws(action, (error: unknown) => {
    assert.ok(error instanceof TransactionAuthorizationError);
    assert.equal(error.code, code);
    return true;
  });
}

test("prepares a valid ALLOW transaction without executing it", async () => {
  await withFixture((fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    const stored = fixture.database.getAuthorizationIntent(prepared.intentId);

    assert.ok(prepared.authorizationToken.length >= 40);
    assert.match(prepared.authorizationToken, /^[A-Za-z0-9_-]+$/);
    assert.equal(prepared.policyVersion, "1");
    assert.equal(prepared.expectedSignerAccountId, "authorized.testnet");
    assert.equal(prepared.recipient, "recipient.testnet");
    assert.equal(prepared.amountYocto, "1");
    assert.equal(prepared.approval, null);
    assert.equal(prepared.executed, false);
    assert.equal(stored?.state, "issued");
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM transactions")
          .get() as { count: number }
      ).count,
      1,
    );
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM chain_verifications")
          .get() as { count: number }
      ).count,
      0,
    );
    assert.equal("transactionHash" in prepared, false);
  });
});

test("WARN preparation requires an approved, correctly linked current approval", async () => {
  await withFixture(
    (fixture) => {
      assertAuthorizationError(
        () => fixture.service.prepare(fixture.transactionId),
        "APPROVAL_REQUIRED",
      );
      assert.equal(
        (
          fixture.database.connection
            .prepare("SELECT count(*) AS count FROM authorization_intents")
            .get() as { count: number }
        ).count,
        0,
      );
    },
    { amountYocto: (2n * NEAR).toString() },
  );

  await withFixture(
    (fixture) => {
      const prepared = fixture.service.prepare(fixture.transactionId);
      assert.deepEqual(prepared.approval, {
        status: "approved",
        reviewerIdentityVerified: false,
      });
    },
    { amountYocto: (2n * NEAR).toString(), approveWarn: true },
  );
});

test("rejects BLOCK decisions", async () => {
  await withFixture(
    (fixture) => {
      assertAuthorizationError(
        () => fixture.service.prepare(fixture.transactionId),
        "POLICY_BLOCKED",
      );
    },
    { amountYocto: (11n * NEAR).toString() },
  );
});

test("rejects disabled agents and missing wallet bindings", async () => {
  await withFixture(
    (fixture) => {
      assertAuthorizationError(
        () => fixture.service.prepare(fixture.transactionId),
        "AGENT_DISABLED",
      );
    },
    { enabled: false },
  );
  await withFixture(
    (fixture) => {
      assertAuthorizationError(
        () => fixture.service.prepare(fixture.transactionId),
        "WALLET_UNBOUND",
      );
    },
    { bindWallet: false },
  );
});

test("rejects stale policy versions, snapshots, and changed evaluation results", async () => {
  await withFixture((fixture) => {
    fixture.database.updatePolicy(fixture.agentId, {
      maxTransactionAmountYocto: "1",
      approvalThresholdYocto: "1",
      deniedRecipients: [],
    });
    assertAuthorizationError(
      () => fixture.service.prepare(fixture.transactionId),
      "STALE_DECISION",
    );
  });

  await withFixture((fixture) => {
    fixture.database.connection
      .prepare("UPDATE transactions SET amount_yocto = ? WHERE id = ?")
      .run((11n * NEAR).toString(), fixture.transactionId);
    assertAuthorizationError(
      () => fixture.service.prepare(fixture.transactionId),
      "STALE_DECISION",
    );
  });
});

test("rejects unsupported network, transaction type, and asset", async () => {
  for (const options of [
    { network: "near-mainnet" },
    { transactionType: "function_call" },
    { asset: "TOKEN" },
  ]) {
    await withFixture(
      (fixture) => {
        assertAuthorizationError(
          () => fixture.service.prepare(fixture.transactionId),
          "UNSUPPORTED_TRANSACTION",
        );
      },
      options,
    );
  }
});

test("returns high-entropy token once and stores only its SHA-256 hash", async () => {
  await withFixture((fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    const stored = fixture.database.getAuthorizationIntent(prepared.intentId)!;
    const expectedHash = createHash("sha256")
      .update(prepared.authorizationToken, "utf8")
      .digest("hex");
    const serializedStorage = JSON.stringify(
      fixture.database.connection
        .prepare("SELECT * FROM authorization_intents WHERE id = ?")
        .get(prepared.intentId),
    );
    const audit = fixture.database.listAudit().find(
      (event) => event.entityId === prepared.intentId,
    );

    assert.match(prepared.authorizationToken, /^[A-Za-z0-9_-]{43}$/);
    assert.equal(stored.tokenHash, expectedHash);
    assert.equal(serializedStorage.includes(prepared.authorizationToken), false);
    assert.equal(JSON.stringify(audit?.details).includes(prepared.authorizationToken), false);
    assert.equal(JSON.stringify(audit?.details).includes(stored.tokenHash), false);
  });

  await withFixture((fixture) => {
    const first = fixture.service.prepare(fixture.transactionId);
    assertAuthorizationError(
      () => fixture.service.prepare(fixture.transactionId),
      "PREPARATION_EXISTS",
    );
    assert.equal(fixture.database.getAuthorizationIntent(first.intentId)?.state, "issued");
    assert.equal(
      (
        fixture.database.connection
          .prepare(
            "SELECT count(*) AS count FROM authorization_intents WHERE transaction_id = ? AND state = 'issued'",
          )
          .get(fixture.transactionId) as { count: number }
      ).count,
      1,
    );
  });

  await withFixture((fixture) => {
    const first = fixture.service.prepare(fixture.transactionId);
    const other = createFixture();
    try {
      const second = other.service.prepare(other.transactionId);
      assert.notEqual(first.authorizationToken, second.authorizationToken);
    } finally {
      other.close();
    }
  });
});

test("authorization intent expires exactly three minutes after creation", async () => {
  await withFixture((fixture) => {
    const before = Date.now();
    const prepared = fixture.service.prepare(fixture.transactionId);
    const after = Date.now();
    const expiresAt = Date.parse(prepared.expiresAt);

    assert.ok(expiresAt >= before + 3 * 60 * 1000);
    assert.ok(expiresAt <= after + 3 * 60 * 1000);
  });
});

test("expired prior preparation is rejected and is not silently replaced", async () => {
  await withFixture((fixture) => {
    const first = fixture.service.prepare(fixture.transactionId);
    fixture.database.connection.exec(
      "DROP TRIGGER authorization_intents_protect_snapshot",
    );
    fixture.database.connection
      .prepare("UPDATE authorization_intents SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), first.intentId);

    assertAuthorizationError(
      () => fixture.service.prepare(fixture.transactionId),
      "PREVIOUS_INTENT_EXPIRED",
    );
    assert.equal(fixture.database.getAuthorizationIntent(first.intentId)?.state, "issued");
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM authorization_intents WHERE transaction_id = ?")
          .get(fixture.transactionId) as { count: number }
      ).count,
      1,
    );
  });
});

test("audit failure rolls back intent creation and returns no authorization token", async () => {
  await withFixture((fixture) => {
    fixture.database.connection.exec(`
      CREATE TRIGGER reject_preparation_audit
      BEFORE INSERT ON audit_logs
      WHEN NEW.event_type = 'authorization_intent.issued'
      BEGIN
        SELECT RAISE(ABORT, 'preparation audit failure');
      END;
    `);

    assert.throws(
      () => fixture.service.prepare(fixture.transactionId),
      /preparation audit failure/,
    );
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM authorization_intents")
          .get() as { count: number }
      ).count,
      0,
    );
  });
});
