import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import {
  SentraDatabase,
  type AgentRecord,
  type AuthorizationIntentRecord,
  type PolicyRecord,
  type TransactionRecord,
  isValidNearTransactionHash,
} from "../database/database.js";
import {
  NearTestnetTransactionVerifier,
  type NearTransactionVerification,
} from "./nearTestnetTransactionVerifier.js";
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

export interface TransactionConfirmationResult {
  intentId: string;
  transactionHash: string;
  status: "verified" | "failed" | "unverified" | "stale" | "expired";
  authorizationIntentState: AuthorizationIntentRecord["state"];
  chainVerificationStatus: NearTransactionVerification["status"] | null;
  verified: boolean;
  reason: string;
  observed: NearTransactionVerification["observed"];
}

export interface AuthorizationRevocationResult {
  intentId: string;
  status: "revoked";
  revokedAt: string;
}

export interface TransactionVerifier {
  verify(expectation: {
    transactionHash: string;
    signerAccountId: string;
    receiverAccountId: string;
    amountYocto: string;
  }): Promise<NearTransactionVerification>;
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
  constructor(
    private readonly database: SentraDatabase,
    private readonly verifier: TransactionVerifier = new NearTestnetTransactionVerifier(),
  ) {}

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

  async confirm(
    intentId: string,
    authorizationToken: string,
    transactionHash: string,
  ): Promise<TransactionConfirmationResult> {
    if (
      typeof intentId !== "string" ||
      intentId.trim().length === 0 ||
      typeof authorizationToken !== "string" ||
      typeof transactionHash !== "string" ||
      !isValidNearTransactionHash(transactionHash)
    ) {
      throw new TransactionAuthorizationError(
        400,
        "INVALID_INPUT",
        "A valid authorization intent ID, token, and NEAR transaction hash are required.",
      );
    }

    const intent = this.database.getAuthorizationIntent(intentId);
    if (!intent) {
      throw new TransactionAuthorizationError(404, "NOT_FOUND", "Authorization intent not found.");
    }
    if (!this.matchesAuthorizationToken(intent, authorizationToken)) {
      throw new TransactionAuthorizationError(
        401,
        "INVALID_AUTHORIZATION_TOKEN",
        "Authorization token is invalid.",
      );
    }
    if (intent.state === "revoked") {
      conflict("AUTHORIZATION_REVOKED", "Authorization intent has been revoked.");
    }
    if (intent.state === "stale") {
      return this.staleResult(intent, transactionHash, "Authorization is no longer eligible.");
    }
    if (intent.state === "expired") {
      return {
        intentId: intent.id,
        transactionHash,
        status: "expired",
        authorizationIntentState: "expired",
        chainVerificationStatus: null,
        verified: false,
        reason: "Authorization intent expired before verification began.",
        observed: null,
      };
    }
    if (intent.state !== "issued" && intent.state !== "indeterminate") {
      conflict(
        "AUTHORIZATION_REPLAY",
        "Authorization intent has already been used or is being verified.",
      );
    }

    const transaction = this.database.getTransaction(intent.transactionId);
    if (!transaction) {
      return this.invalidateAsStale(intent, transactionHash, "Saved transaction is unavailable.");
    }
    if (
      transaction.network !== "near-testnet" ||
      transaction.transactionType !== "native_transfer" ||
      transaction.asset !== "NEAR" ||
      transaction.status !== transaction.decision.decision ||
      !["ALLOW", "WARN"].includes(transaction.decision.decision)
    ) {
      return this.invalidateAsStale(
        intent,
        transactionHash,
        "Saved transaction no longer matches an eligible native NEAR transfer.",
      );
    }

    const started = this.database.startAuthorizationIntentVerification(
      intent.id,
      transactionHash,
      intent.authorizedWalletAccountId,
    );
    if (!started) {
      const current = this.database.getAuthorizationIntent(intent.id);
      if (current?.state === "revoked") {
        conflict("AUTHORIZATION_REVOKED", "Authorization intent has been revoked.");
      }
      if (current?.state === "stale") {
        return this.staleResult(current, transactionHash, "Authorization is no longer eligible.");
      }
      if (current?.state === "expired") {
        return {
          intentId: intent.id,
          transactionHash,
          status: "expired",
          authorizationIntentState: "expired",
          chainVerificationStatus: null,
          verified: false,
          reason: "Authorization intent expired before verification began.",
          observed: null,
        };
      }
      if (
        current?.state === "indeterminate" &&
        current.transactionHash !== transactionHash
      ) {
        conflict(
          "TRANSACTION_HASH_MISMATCH",
          "An indeterminate authorization can only retry verification for the same transaction hash.",
        );
      }
      const priorVerification =
        this.database.getChainVerificationByTransactionHash(transactionHash);
      if (priorVerification && priorVerification.authorizationIntentId !== intent.id) {
        conflict(
          "TRANSACTION_HASH_REPLAY",
          "This NEAR transaction hash has already been associated with another authorization intent.",
        );
      }
      conflict(
        "AUTHORIZATION_REPLAY",
        "Authorization intent has already been used or is being verified.",
      );
    }

    let verification: NearTransactionVerification;
    try {
      verification = await this.verifier.verify({
        transactionHash,
        signerAccountId: started.authorizedWalletAccountId,
        receiverAccountId: transaction.recipient,
        amountYocto: transaction.amountYocto,
      });
    } catch {
      verification = {
        status: "unverified",
        verified: false,
        transactionHash,
        finality: null,
        reasons: [{
          code: "VERIFIER_ERROR",
          message: "Verifier could not complete; transaction outcome remains unverified.",
        }],
        observed: null,
      };
    }
    if (
      verification.transactionHash !== transactionHash ||
      (verification.status === "verified" && !verification.verified)
    ) {
      verification = {
        status: "unverified",
        verified: false,
        transactionHash,
        finality: verification.finality,
        reasons: [{
          code: "INVALID_VERIFIER_RESULT",
          message: "Verifier returned an inconsistent result; transaction outcome remains unverified.",
        }],
        observed: verification.observed,
      };
    }

    const reason = verification.reasons
      .map((item) => `${item.code}: ${item.message}`)
      .join("; ");
    const completed = this.database.completeAuthorizationIntentVerification({
      authorizationIntentId: started.id,
      transactionHash,
      status: verification.status,
      reason,
      observedSignerAccountId: verification.observed?.signerAccountId ?? null,
      observedReceiverAccountId: verification.observed?.receiverAccountId ?? null,
      observedAmountYocto: verification.observed?.amountYocto ?? null,
      verifiedAt: new Date().toISOString(),
    });

    if (completed.authorizationIntentState === "stale") {
      return {
        intentId: intent.id,
        transactionHash,
        status: "stale",
        authorizationIntentState: "stale",
        chainVerificationStatus: verification.status,
        verified: false,
        reason: "Authorization became stale or expired while verification was in progress.",
        observed: verification.observed,
      };
    }
    return {
      intentId: intent.id,
      transactionHash,
      status: verification.status,
      authorizationIntentState: completed.authorizationIntentState,
      chainVerificationStatus: verification.status,
      verified: verification.status === "verified",
      reason,
      observed: verification.observed,
    };
  }

  revoke(
    intentId: string,
    authorizationToken: string,
  ): AuthorizationRevocationResult {
    if (
      typeof intentId !== "string" ||
      intentId.trim().length === 0 ||
      typeof authorizationToken !== "string"
    ) {
      throw new TransactionAuthorizationError(
        400,
        "INVALID_INPUT",
        "A valid authorization intent ID and token are required.",
      );
    }

    const intent = this.database.getAuthorizationIntent(intentId);
    if (!intent) {
      throw new TransactionAuthorizationError(404, "NOT_FOUND", "Authorization intent not found.");
    }
    if (!this.matchesAuthorizationToken(intent, authorizationToken)) {
      throw new TransactionAuthorizationError(
        401,
        "INVALID_AUTHORIZATION_TOKEN",
        "Authorization token is invalid.",
      );
    }
    if (intent.state === "revoked") {
      conflict("AUTHORIZATION_REVOKED", "Authorization intent has already been revoked.");
    }
    if (intent.state === "expired" || Date.parse(intent.expiresAt) <= Date.now()) {
      const result = this.database.revokeAuthorizationIntent(intentId, intent.tokenHash);
      if (result.status === "expired") {
        conflict("AUTHORIZATION_EXPIRED", "Expired authorization intents cannot be revoked or reused.");
      }
      conflict("AUTHORIZATION_NOT_REVOCABLE", "Authorization intent is no longer eligible for revocation.");
    }
    if (intent.state !== "issued") {
      conflict(
        "AUTHORIZATION_NOT_REVOCABLE",
        "Only an issued authorization intent can be revoked.",
      );
    }

    const result = this.database.revokeAuthorizationIntent(intentId, intent.tokenHash);
    if (result.status === "revoked" && result.intent && result.revokedAt) {
      return {
        intentId: result.intent.id,
        status: "revoked",
        revokedAt: result.revokedAt,
      };
    }
    if (result.status === "expired") {
      conflict("AUTHORIZATION_EXPIRED", "Expired authorization intents cannot be revoked or reused.");
    }
    if (result.status === "stale") {
      conflict("AUTHORIZATION_STALE", "Authorization eligibility changed before revocation.");
    }
    const current = this.database.getAuthorizationIntent(intentId);
    if (current?.state === "revoked") {
      conflict("AUTHORIZATION_REVOKED", "Authorization intent has already been revoked.");
    }
    if (current?.state === "expired") {
      conflict("AUTHORIZATION_EXPIRED", "Expired authorization intents cannot be revoked or reused.");
    }
    conflict(
      "AUTHORIZATION_NOT_REVOCABLE",
      "Authorization intent is being verified or is no longer eligible for revocation.",
    );
  }

  private matchesAuthorizationToken(
    intent: AuthorizationIntentRecord,
    token: string,
  ): boolean {
    if (!/^[A-Za-z0-9_-]{43}$/.test(token) || !/^[0-9a-f]{64}$/.test(intent.tokenHash)) {
      return false;
    }
    const expectedHash = Buffer.from(intent.tokenHash, "hex");
    const providedHash = createHash("sha256").update(token, "utf8").digest();
    return expectedHash.length === providedHash.length &&
      timingSafeEqual(expectedHash, providedHash);
  }

  private invalidateAsStale(
    intent: AuthorizationIntentRecord,
    transactionHash: string,
    reason: string,
  ): TransactionConfirmationResult {
    const updated = this.database.invalidateAuthorizationIntent(intent.id, "stale", reason);
    return this.staleResult(updated ?? intent, transactionHash, reason);
  }

  private staleResult(
    intent: AuthorizationIntentRecord,
    transactionHash: string,
    reason: string,
  ): TransactionConfirmationResult {
    return {
      intentId: intent.id,
      transactionHash,
      status: "stale",
      authorizationIntentState: intent.state,
      chainVerificationStatus: null,
      verified: false,
      reason,
      observed: null,
    };
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
