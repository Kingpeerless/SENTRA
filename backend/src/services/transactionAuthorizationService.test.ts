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
  type TransactionVerifier,
} from "./transactionAuthorizationService.js";
import type { NearTransactionVerification } from "./nearTestnetTransactionVerifier.js";

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

const TEST_TRANSACTION_HASH = "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS";

function mockedVerifier(
  createResult: (
    expectation: Parameters<TransactionVerifier["verify"]>[0],
  ) => NearTransactionVerification | Promise<NearTransactionVerification>,
): TransactionVerifier {
  return { verify: async (expectation) => createResult(expectation) };
}

function verifiedResult(
  expectation: Parameters<TransactionVerifier["verify"]>[0],
): NearTransactionVerification {
  return {
    status: "verified",
    verified: true,
    transactionHash: expectation.transactionHash,
    finality: "FINAL",
    reasons: [{ code: "VERIFIED", message: "Finalized native transfer matched." }],
    observed: {
      signerAccountId: expectation.signerAccountId,
      receiverAccountId: expectation.receiverAccountId,
      actionCount: 1,
      actionType: "Transfer",
      amountYocto: expectation.amountYocto,
    },
  };
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

test("confirmation verifies only persisted transaction expectations and records an audit trail", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    let receivedExpectation: Parameters<TransactionVerifier["verify"]>[0] | undefined;
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier((expectation) => {
        receivedExpectation = expectation;
        return verifiedResult(expectation);
      }),
    );

    const result = await confirmation.confirm(
      prepared.intentId,
      prepared.authorizationToken,
      TEST_TRANSACTION_HASH,
    );
    assert.deepEqual(receivedExpectation, {
      transactionHash: TEST_TRANSACTION_HASH,
      signerAccountId: "authorized.testnet",
      receiverAccountId: "recipient.testnet",
      amountYocto: "1",
    });
    assert.equal(result.status, "verified");
    assert.equal(result.verified, true);
    assert.equal(result.authorizationIntentState, "verified");
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "verified");
    assert.equal(
      fixture.database.getChainVerification(prepared.intentId)?.status,
      "verified",
    );
    const audit = fixture.database.listAudit().filter((event) => event.entityId === prepared.intentId);
    assert.ok(audit.some((event) => event.eventType === "authorization_intent.verification_started"));
    assert.ok(audit.some((event) => event.eventType === "chain_verification.completed"));
    assert.equal(JSON.stringify(audit).includes(prepared.authorizationToken), false);
  });
});

test("WARN confirmation proceeds only with its current approved record", async () => {
  await withFixture(
    async (fixture) => {
      const prepared = fixture.service.prepare(fixture.transactionId);
      assert.equal(prepared.approval?.status, "approved");
      const confirmation = new TransactionAuthorizationService(
        fixture.database,
        mockedVerifier(verifiedResult),
      );
      const result = await confirmation.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      );
      assert.equal(result.status, "verified");
      assert.equal(result.verified, true);
    },
    { amountYocto: (2n * NEAR).toString(), approveWarn: true },
  );
});

test("invalid tokens and replayed confirmations never invoke the verifier", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    let verifierCalls = 0;
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier((expectation) => {
        verifierCalls += 1;
        return verifiedResult(expectation);
      }),
    );

    await assert.rejects(
      confirmation.confirm(prepared.intentId, `${prepared.authorizationToken}x`, TEST_TRANSACTION_HASH),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "INVALID_AUTHORIZATION_TOKEN",
    );
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "issued");

    await confirmation.confirm(
      prepared.intentId,
      prepared.authorizationToken,
      TEST_TRANSACTION_HASH,
    );
    await assert.rejects(
      confirmation.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      ),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "AUTHORIZATION_REPLAY",
    );
    assert.equal(verifierCalls, 1);
  });
});

test("valid revocation consumes an issued intent, records an audit event, and blocks confirmation", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    const result = fixture.service.revoke(prepared.intentId, prepared.authorizationToken);
    assert.equal(result.intentId, prepared.intentId);
    assert.equal(result.status, "revoked");
    assert.equal("tokenHash" in result, false);
    assert.equal("authorizationToken" in result, false);
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "revoked");

    const rawState = fixture.database.connection
      .prepare("SELECT state FROM authorization_intents WHERE id = ?")
      .get(prepared.intentId) as { state: string };
    assert.equal(rawState.state, "issued");
    assert.ok(
      fixture.database.listAudit().some(
        (event) =>
          event.entityId === prepared.intentId &&
          event.eventType === "authorization_intent.revoked",
      ),
    );
    assertAuthorizationError(
      () => fixture.service.revoke(prepared.intentId, prepared.authorizationToken),
      "AUTHORIZATION_REVOKED",
    );
    await assert.rejects(
      fixture.service.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      ),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "AUTHORIZATION_REVOKED",
    );
  });
});

test("invalid and expired tokens cannot revoke or revive an authorization intent", async () => {
  await withFixture((fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    assertAuthorizationError(
      () => fixture.service.revoke(prepared.intentId, `${prepared.authorizationToken}x`),
      "INVALID_AUTHORIZATION_TOKEN",
    );
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "issued");

    fixture.database.connection.exec("DROP TRIGGER authorization_intents_protect_snapshot");
    fixture.database.connection
      .prepare("UPDATE authorization_intents SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), prepared.intentId);
    assertAuthorizationError(
      () => fixture.service.revoke(prepared.intentId, prepared.authorizationToken),
      "AUTHORIZATION_EXPIRED",
    );
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "expired");
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM authorization_intent_revocations")
          .get() as { count: number }
      ).count,
      0,
    );
  });
});

test("revocation and in-flight verification have a single safe winner", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    let markVerifierEntered!: () => void;
    let finishVerifier!: () => void;
    const verifierEntered = new Promise<void>((resolve) => {
      markVerifierEntered = resolve;
    });
    const verifierMayFinish = new Promise<void>((resolve) => {
      finishVerifier = resolve;
    });
    const confirmationService = new TransactionAuthorizationService(fixture.database, {
      async verify(expectation) {
        markVerifierEntered();
        await verifierMayFinish;
        return verifiedResult(expectation);
      },
    });

    const confirmation = confirmationService.confirm(
      prepared.intentId,
      prepared.authorizationToken,
      TEST_TRANSACTION_HASH,
    );
    await verifierEntered;
    assertAuthorizationError(
      () => fixture.service.revoke(prepared.intentId, prepared.authorizationToken),
      "AUTHORIZATION_NOT_REVOCABLE",
    );
    finishVerifier();
    const confirmed = await confirmation;
    assert.equal(confirmed.status, "verified");
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "verified");
    assert.equal(
      (
        fixture.database.connection
          .prepare("SELECT count(*) AS count FROM authorization_intent_revocations")
          .get() as { count: number }
      ).count,
      0,
    );
  });

  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    fixture.service.revoke(prepared.intentId, prepared.authorizationToken);
    await assert.rejects(
      fixture.service.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      ),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "AUTHORIZATION_REVOKED",
    );
  });
});

test("expired and stale authorizations are distinguished and are not verified", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    fixture.database.connection.exec("DROP TRIGGER authorization_intents_protect_snapshot");
    fixture.database.connection
      .prepare("UPDATE authorization_intents SET expires_at = ? WHERE id = ?")
      .run(new Date(Date.now() - 1000).toISOString(), prepared.intentId);
    let verifierCalls = 0;
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier(() => {
        verifierCalls += 1;
        return Promise.reject(new Error("Must not call verifier."));
      }),
    );

    const expired = await confirmation.confirm(
      prepared.intentId,
      prepared.authorizationToken,
      TEST_TRANSACTION_HASH,
    );
    assert.equal(expired.status, "expired");
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "expired");
    assert.equal(verifierCalls, 0);
  });

  for (const change of ["policy", "agent"] as const) {
    await withFixture(async (fixture) => {
      const prepared = fixture.service.prepare(fixture.transactionId);
      if (change === "policy") {
        fixture.database.updatePolicy(fixture.agentId, {
          maxTransactionAmountYocto: (10n * NEAR).toString(),
          approvalThresholdYocto: NEAR.toString(),
          deniedRecipients: ["other.testnet"],
        });
      } else {
        fixture.database.setAgentEnabled(fixture.agentId, false);
      }
      let verifierCalls = 0;
      const confirmation = new TransactionAuthorizationService(
        fixture.database,
        mockedVerifier(() => {
          verifierCalls += 1;
          return Promise.reject(new Error("Must not call verifier."));
        }),
      );
      const stale = await confirmation.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      );
      assert.equal(stale.status, "stale");
      assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "stale");
      assert.equal(verifierCalls, 0);
    });
  }
});

test("authorization expiry during RPC prevents a verified authorization result", async () => {
  await withFixture(async (fixture) => {
    const prepared = fixture.service.prepare(fixture.transactionId);
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier((expectation) => {
        fixture.database.connection.exec(
          "DROP TRIGGER authorization_intents_protect_snapshot",
        );
        fixture.database.connection
          .prepare("UPDATE authorization_intents SET expires_at = ? WHERE id = ?")
          .run(new Date(Date.now() - 1000).toISOString(), prepared.intentId);
        return verifiedResult(expectation);
      }),
    );
    const result = await confirmation.confirm(
      prepared.intentId,
      prepared.authorizationToken,
      TEST_TRANSACTION_HASH,
    );

    assert.equal(result.status, "stale");
    assert.equal(result.chainVerificationStatus, "verified");
    assert.equal(result.verified, false);
    assert.equal(fixture.database.getAuthorizationIntent(prepared.intentId)?.state, "stale");
    assert.equal(fixture.database.getChainVerification(prepared.intentId)?.status, "verified");
  });
});

test("a transaction hash already used by another intent is rejected before RPC", async () => {
  await withFixture(async (fixture) => {
    const first = fixture.service.prepare(fixture.transactionId);
    let verifierCalls = 0;
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier((expectation) => {
        verifierCalls += 1;
        return verifiedResult(expectation);
      }),
    );
    await confirmation.confirm(first.intentId, first.authorizationToken, TEST_TRANSACTION_HASH);

    const agent = fixture.database.getAgent(fixture.agentId)!;
    const policy = fixture.database.getCurrentPolicy(fixture.agentId)!;
    const secondTransaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "1",
      asset: "NEAR",
      reason: "Separate transaction for replay testing",
    };
    const secondDecision = evaluateTransaction(secondTransaction, agent, {
      version: policy.version,
      maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policy.approvalThresholdYocto,
      deniedRecipients: policy.deniedRecipients,
    });
    const secondEvaluation = fixture.database.createEvaluation({
      agentId: agent.id,
      transaction: secondTransaction,
      result: secondDecision,
      policy,
    });
    const second = fixture.service.prepare(secondEvaluation.transactionId);

    await assert.rejects(
      confirmation.confirm(second.intentId, second.authorizationToken, TEST_TRANSACTION_HASH),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "TRANSACTION_HASH_REPLAY",
    );
    assert.equal(verifierCalls, 1);
    assert.equal(fixture.database.getAuthorizationIntent(second.intentId)?.state, "issued");
  });
});

test("the same transaction hash cannot be claimed by concurrent intents", async () => {
  await withFixture(async (fixture) => {
    const first = fixture.service.prepare(fixture.transactionId);
    let resolveVerification!: (result: NearTransactionVerification) => void;
    let firstExpectation!: Parameters<TransactionVerifier["verify"]>[0];
    const verificationPending = new Promise<NearTransactionVerification>((resolve) => {
      resolveVerification = resolve;
    });
    const confirmation = new TransactionAuthorizationService(
      fixture.database,
      mockedVerifier((expectation) => {
        firstExpectation = expectation;
        return verificationPending;
      }),
    );
    const firstConfirmation = confirmation.confirm(
      first.intentId,
      first.authorizationToken,
      TEST_TRANSACTION_HASH,
    );

    const agent = fixture.database.getAgent(fixture.agentId)!;
    const policy = fixture.database.getCurrentPolicy(fixture.agentId)!;
    const transaction = {
      agentId: agent.id,
      network: "near-testnet",
      transactionType: "native_transfer",
      recipient: "recipient.testnet",
      amountYocto: "1",
      asset: "NEAR",
      reason: "Concurrent replay testing",
    };
    const decision = evaluateTransaction(transaction, agent, {
      version: policy.version,
      maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
      approvalThresholdYocto: policy.approvalThresholdYocto,
      deniedRecipients: policy.deniedRecipients,
    });
    const evaluation = fixture.database.createEvaluation({
      agentId: agent.id,
      transaction,
      result: decision,
      policy,
    });
    const second = fixture.service.prepare(evaluation.transactionId);

    await assert.rejects(
      confirmation.confirm(second.intentId, second.authorizationToken, TEST_TRANSACTION_HASH),
      (error: unknown) =>
        error instanceof TransactionAuthorizationError &&
        error.code === "AUTHORIZATION_REPLAY",
    );
    resolveVerification(verifiedResult(firstExpectation));
    assert.equal((await firstConfirmation).status, "verified");
    assert.equal(fixture.database.getAuthorizationIntent(second.intentId)?.state, "issued");
  });
});

test("wrong hashes, signers, recipients, and amounts remain unverified", async () => {
  const mismatches = [
    { reason: "TRANSACTION_UNKNOWN", signer: "authorized.testnet", receiver: "recipient.testnet", amount: "1" },
    { reason: "SIGNER_MISMATCH", signer: "attacker.testnet", receiver: "recipient.testnet", amount: "1" },
    { reason: "RECEIVER_MISMATCH", signer: "authorized.testnet", receiver: "other.testnet", amount: "1" },
    { reason: "AMOUNT_MISMATCH", signer: "authorized.testnet", receiver: "recipient.testnet", amount: "2" },
  ];

  for (const [index, mismatch] of mismatches.entries()) {
    await withFixture(async (fixture) => {
      const prepared = fixture.service.prepare(fixture.transactionId);
      const confirmation = new TransactionAuthorizationService(
        fixture.database,
        mockedVerifier((expectation) => ({
          status: "unverified",
          verified: false,
          transactionHash: expectation.transactionHash,
          finality: index === 0 ? null : "FINAL",
          reasons: [{ code: mismatch.reason, message: "Expected values did not match." }],
          observed: {
            signerAccountId: mismatch.signer,
            receiverAccountId: mismatch.receiver,
            actionCount: 1,
            actionType: "Transfer",
            amountYocto: mismatch.amount,
          },
        })),
      );
      const result = await confirmation.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        index === 0 ? "7zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS" : TEST_TRANSACTION_HASH,
      );
      assert.equal(result.status, "unverified");
      assert.equal(result.verified, false);
      assert.equal(fixture.database.getChainVerification(prepared.intentId)?.status, "unverified");
      assert.match(result.reason, new RegExp(mismatch.reason));
    });
  }
});

test("finalized failure, pending and unavailable RPC outcomes are never reported as success", async () => {
  const outcomes: Array<{
    status: NearTransactionVerification["status"] | "throws";
    expected: "failed" | "unverified";
  }> = [
    { status: "failed", expected: "failed" },
    { status: "unverified", expected: "unverified" },
    { status: "throws", expected: "unverified" },
  ];
  for (const outcome of outcomes) {
    await withFixture(async (fixture) => {
      const prepared = fixture.service.prepare(fixture.transactionId);
      const confirmation = new TransactionAuthorizationService(
        fixture.database,
        mockedVerifier((expectation) => {
          if (outcome.status === "throws") throw new Error("RPC unavailable");
          return {
            status: outcome.status,
            verified: false,
            transactionHash: expectation.transactionHash,
            finality: outcome.status === "failed" ? "FINAL" : null,
            reasons: [{
              code: outcome.status === "failed" ? "TRANSACTION_FAILED" : "RPC_UNAVAILABLE",
              message: "Outcome is not a verified success.",
            }],
            observed: null,
          };
        }),
      );
      const result = await confirmation.confirm(
        prepared.intentId,
        prepared.authorizationToken,
        TEST_TRANSACTION_HASH,
      );
      assert.equal(result.status, outcome.expected);
      assert.equal(result.verified, false);
      assert.equal(fixture.database.getChainVerification(prepared.intentId)?.status, outcome.expected);
      assert.equal(
        fixture.database.getAuthorizationIntent(prepared.intentId)?.state,
        outcome.expected === "failed" ? "failed" : "indeterminate",
      );
    });
  }
});
