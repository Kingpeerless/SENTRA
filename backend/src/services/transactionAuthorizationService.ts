import { createHash, randomBytes } from "node:crypto";
import {
  SentraDatabase,
  type AgentRecord,
  type AuthorizationIntentRecord,
  type PolicyRecord,
  type TransactionRecord,
} from "../database/database.js";
import {
  evaluateTransaction,
  type Policy,
  type PolicyDecision,
  type Transaction,
} from "../engine/policyEngine.js";

const INTENT_LIFETIME_MS = 3 * 60 * 1000;

export class TransactionAuthorizationError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "TransactionAuthorizationError";
  }
}

export interface PreparedTransactionAuthorization {
  intentId: string;
  authorizationToken: string;
  expiresAt: string;
  policyVersion: string;
  expectedSignerAccountId: string;
  recipient: string;
  amountYocto: string;
  approval: {
    status: "approved";
    reviewerIdentityVerified: false;
  } | null;
  executed: false;
}

function policyFromRecord(policy: PolicyRecord): Policy {
  return {
    version: policy.version,
    maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
    approvalThresholdYocto: policy.approvalThresholdYocto,
    deniedRecipients: policy.deniedRecipients,
  };
}

function transactionFromRecord(record: TransactionRecord): Transaction {
  return {
    agentId: record.agentId,
    network: record.network,
    transactionType: record.transactionType,
    recipient: record.recipient,
    amountYocto: record.amountYocto,
    asset: record.asset,
    reason: record.reason,
  };
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function decisionMatches(
  current: PolicyDecision,
  stored: TransactionRecord["decision"],
  record: TransactionRecord,
): boolean {
  return (
    current.decision === stored.decision &&
    current.policyVersion === stored.policyVersion &&
    sameStrings(current.reasons, stored.reasons) &&
    sameStrings(current.triggeredRules, stored.triggeredRules) &&
    current.evaluatedTransaction !== null &&
    current.evaluatedTransaction.agentId === record.agentId &&
    current.evaluatedTransaction.network === record.network &&
    current.evaluatedTransaction.transactionType === record.transactionType &&
    current.evaluatedTransaction.recipient === record.recipient &&
    current.evaluatedTransaction.amountYocto === record.amountYocto &&
    current.evaluatedTransaction.asset === record.asset
  );
}

function conflict(code: string, message: string): never {
  throw new TransactionAuthorizationError(409, code, message);
}

export class TransactionAuthorizationService {
  constructor(private readonly database: SentraDatabase) {}

  prepare(transactionId: string): PreparedTransactionAuthorization {
    if (typeof transactionId !== "string" || transactionId.trim().length === 0) {
      throw new TransactionAuthorizationError(
        400,
        "INVALID_INPUT",
        "A transaction ID is required.",
      );
    }

    const prepareInTransaction = this.database.connection.transaction(() => {
      const transactionRecord = this.database.getTransaction(transactionId);
      if (!transactionRecord) {
        throw new TransactionAuthorizationError(404, "NOT_FOUND", "Transaction not found.");
      }

      const agent = this.database.getAgent(transactionRecord.agentId);
      if (!agent) {
        throw new TransactionAuthorizationError(404, "NOT_FOUND", "Transaction agent not found.");
      }
      this.requireEligibleAgent(agent);

      const currentPolicy = this.database.getCurrentPolicy(agent.id);
      if (!currentPolicy) {
        throw new TransactionAuthorizationError(
          500,
          "INTERNAL_ERROR",
          "Agent policy is unavailable.",
        );
      }
      this.requireSupportedTransaction(transactionRecord);

      const originalDecision = transactionRecord.decision;
      if (transactionRecord.status === "BLOCK" || originalDecision.decision === "BLOCK") {
        conflict("POLICY_BLOCKED", "BLOCK decisions cannot be prepared.");
      }
      if (originalDecision.policyVersion !== currentPolicy.version) {
        conflict("STALE_DECISION", "Policy changed; re-evaluate the transaction before preparing.");
      }
      if (!this.policySnapshotMatches(originalDecision.policySnapshot, currentPolicy)) {
        conflict("STALE_DECISION", "Saved policy snapshot is stale; re-evaluate the transaction.");
      }

      const currentDecision = evaluateTransaction(
        transactionFromRecord(transactionRecord),
        { id: agent.id, enabled: agent.enabled },
        policyFromRecord(currentPolicy),
      );
      if (
        transactionRecord.status !== originalDecision.decision ||
        !decisionMatches(currentDecision, originalDecision, transactionRecord)
      ) {
        conflict("STALE_DECISION", "Transaction decision changed; re-evaluate before preparing.");
      }
      if (currentDecision.decision === "BLOCK") {
        conflict("POLICY_BLOCKED", "Current policy blocks this transaction.");
      }

      const approval = currentDecision.decision === "WARN"
        ? this.requireApprovedWarn(transactionRecord, currentPolicy)
        : null;

      this.rejectDuplicatePreparation(transactionId);

      const authorizationToken = randomBytes(32).toString("base64url");
      const tokenHash = createHash("sha256")
        .update(authorizationToken, "utf8")
        .digest("hex");
      const expiresAt = new Date(Date.now() + INTENT_LIFETIME_MS).toISOString();
      const intent = this.database.createAuthorizationIntent({
        transactionId: transactionRecord.id,
        decisionId: originalDecision.id,
        approvalId: approval?.id ?? null,
        tokenHash,
        policyId: currentPolicy.id,
        policyVersion: currentPolicy.version,
        authorizedWalletAccountId: agent.authorizedNearAccountId!,
        expiresAt,
      });

      return this.toResponse(
        intent,
        authorizationToken,
        agent,
        transactionRecord,
        approval !== null,
      );
    });

    return prepareInTransaction.immediate();
  }

  private requireEligibleAgent(agent: AgentRecord): void {
    if (!agent.enabled) {
      conflict("AGENT_DISABLED", "Disabled agents cannot prepare transactions.");
    }
    if (agent.authorizedNearAccountId === null) {
      conflict("WALLET_UNBOUND", "Agent has no authorized NEAR testnet account.");
    }
  }

  private requireSupportedTransaction(transaction: TransactionRecord): void {
    if (
      transaction.network !== "near-testnet" ||
      transaction.transactionType !== "native_transfer" ||
      transaction.asset !== "NEAR"
    ) {
      conflict(
        "UNSUPPORTED_TRANSACTION",
        "Only native NEAR transfers on near-testnet can be prepared.",
      );
    }
  }

  private policySnapshotMatches(
    snapshot: Policy,
    current: PolicyRecord,
  ): boolean {
    return (
      snapshot.version === current.version &&
      snapshot.maxTransactionAmountYocto === current.maxTransactionAmountYocto &&
      snapshot.approvalThresholdYocto === current.approvalThresholdYocto &&
      sameStrings(snapshot.deniedRecipients, current.deniedRecipients)
    );
  }

  private requireApprovedWarn(
    transaction: TransactionRecord,
    policy: PolicyRecord,
  ) {
    const approval = this.database.listApprovals().find(
      (candidate) =>
        candidate.decisionId === transaction.decision.id &&
        candidate.transactionId === transaction.id,
    );
    if (
      !approval ||
      approval.status !== "approved" ||
      approval.decision !== "WARN" ||
      approval.agentId !== transaction.agentId ||
      approval.policyVersion !== policy.version
    ) {
      conflict(
        "APPROVAL_REQUIRED",
        "A current approved WARN record linked to this decision is required.",
      );
    }
    return approval;
  }

  private rejectDuplicatePreparation(transactionId: string): void {
    const rows = this.database.connection
      .prepare(
        `SELECT id, state, expires_at
         FROM authorization_intents
         WHERE transaction_id = ?
         ORDER BY created_at DESC, id`,
      )
      .all(transactionId) as Array<{
      id: string;
      state: AuthorizationIntentRecord["state"];
      expires_at: string;
    }>;
    if (rows.length === 0) return;

    const now = Date.now();
    for (const row of rows) {
      if (
        (row.state === "issued" || row.state === "indeterminate") &&
        Date.parse(row.expires_at) <= now
      ) {
        conflict(
          "PREVIOUS_INTENT_EXPIRED",
          "The prior authorization intent expired; create a new transaction evaluation before preparing again.",
        );
      }
    }
    conflict(
      "PREPARATION_EXISTS",
      "This transaction already has an authorization intent and cannot be prepared again.",
    );
  }

  private toResponse(
    intent: AuthorizationIntentRecord,
    authorizationToken: string,
    agent: AgentRecord,
    transaction: TransactionRecord,
    hasApprovedWarn: boolean,
  ): PreparedTransactionAuthorization {
    return {
      intentId: intent.id,
      authorizationToken,
      expiresAt: intent.expiresAt,
      policyVersion: intent.policyVersion,
      expectedSignerAccountId: agent.authorizedNearAccountId!,
      recipient: transaction.recipient,
      amountYocto: transaction.amountYocto,
      approval: hasApprovedWarn
        ? { status: "approved", reviewerIdentityVerified: false }
        : null,
      executed: false,
    };
  }
}
