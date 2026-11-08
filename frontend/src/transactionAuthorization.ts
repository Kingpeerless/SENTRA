import { authenticatedApiFetch } from "./apiAccess.ts";

export type TransactionDecision = "ALLOW" | "WARN" | "BLOCK";

export interface SavedTransaction {
  id: string;
  agentId: string;
  network: string;
  transactionType: string;
  recipient: string;
  amountYocto: string;
  asset: string;
  status: TransactionDecision;
  createdAt: string;
  decision: {
    id: string;
    decision: TransactionDecision;
    reasons: string[];
    triggeredRules: string[];
    policyVersion: string;
    createdAt: string;
  };
}

export interface SavedApproval {
  id: string;
  decisionId: string;
  status: "pending" | "approved" | "rejected";
  transactionId: string;
  agentId: string;
  decision: TransactionDecision;
  policyVersion: string;
  createdAt: string;
}

export interface PreparedAuthorization {
  intentId: string;
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

export interface PreparedAuthorizationResponse extends PreparedAuthorization {
  authorizationToken: string;
}

export interface TemporaryAuthorizationToken {
  intentId: string;
  transactionId: string;
  agentId: string;
  expectedSignerAccountId: string;
  token: string;
  expiresAt: number;
}

export type TemporaryTokenRef = { current: TemporaryAuthorizationToken | null };
export type TemporaryTokenClearReason =
  | "expired"
  | "wallet-disconnected"
  | "account-changed"
  | "agent-changed"
  | "intent-replaced"
  | "consumed"
  | "invalidated"
  | "session-ended";

export type ActiveWalletNetworkStatus = "verified" | "unverified";

export function isSigningEligibleForNetwork(
  status: ActiveWalletNetworkStatus,
): boolean {
  return status === "verified";
}

export type WarnApprovalStatus = "approved" | "pending" | "rejected" | "missing";

const DECISIONS = new Set<TransactionDecision>(["ALLOW", "WARN", "BLOCK"]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDecision(value: unknown): value is TransactionDecision {
  return typeof value === "string" && DECISIONS.has(value as TransactionDecision);
}

function parseStringArray(value: unknown, description: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`SENTRA returned malformed ${description}.`);
  }
  return value;
}

function parseTransaction(value: unknown): SavedTransaction {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.agentId !== "string" ||
    typeof value.network !== "string" ||
    typeof value.transactionType !== "string" ||
    typeof value.recipient !== "string" ||
    typeof value.amountYocto !== "string" ||
    typeof value.asset !== "string" ||
    !isDecision(value.status) ||
    typeof value.createdAt !== "string" ||
    !isRecord(value.decision) ||
    typeof value.decision.id !== "string" ||
    !isDecision(value.decision.decision) ||
    typeof value.decision.policyVersion !== "string" ||
    typeof value.decision.createdAt !== "string"
  ) {
    throw new Error("SENTRA returned malformed saved transaction data.");
  }

  if (value.status !== value.decision.decision) {
    throw new Error("SENTRA returned inconsistent saved transaction decision data.");
  }

  return {
    id: value.id,
    agentId: value.agentId,
    network: value.network,
    transactionType: value.transactionType,
    recipient: value.recipient,
    amountYocto: value.amountYocto,
    asset: value.asset,
    status: value.status,
    createdAt: value.createdAt,
    decision: {
      id: value.decision.id,
      decision: value.decision.decision,
      reasons: parseStringArray(value.decision.reasons, "transaction reasons"),
      triggeredRules: parseStringArray(value.decision.triggeredRules, "triggered policy rules"),
      policyVersion: value.decision.policyVersion,
      createdAt: value.decision.createdAt,
    },
  };
}

export function parseTransactionsResponse(payload: unknown): SavedTransaction[] {
  if (!isRecord(payload) || !Array.isArray(payload.data)) {
    throw new Error("SENTRA returned an invalid saved transactions response.");
  }
  return payload.data.map(parseTransaction);
}

function parseApproval(value: unknown): SavedApproval {
  if (
    !isRecord(value) ||
    typeof value.id !== "string" ||
    typeof value.decisionId !== "string" ||
    !["pending", "approved", "rejected"].includes(String(value.status)) ||
    typeof value.transactionId !== "string" ||
    typeof value.agentId !== "string" ||
    !isDecision(value.decision) ||
    typeof value.policyVersion !== "string" ||
    typeof value.createdAt !== "string" ||
    !Number.isFinite(Date.parse(value.createdAt))
  ) {
    throw new Error("SENTRA returned malformed transaction approval data.");
  }

  return {
    id: value.id,
    decisionId: value.decisionId,
    status: value.status as SavedApproval["status"],
    transactionId: value.transactionId,
    agentId: value.agentId,
    decision: value.decision,
    policyVersion: value.policyVersion,
    createdAt: new Date(value.createdAt).toISOString(),
  };
}

export function parseApprovalsResponse(payload: unknown): SavedApproval[] {
  if (!isRecord(payload) || !Array.isArray(payload.data)) {
    throw new Error("SENTRA returned an invalid approvals response.");
  }
  return payload.data.map(parseApproval);
}

export function getWarnApprovalStatus(
  transaction: SavedTransaction,
  approvals: readonly SavedApproval[],
): WarnApprovalStatus {
  if (transaction.decision.decision !== "WARN") return "missing";

  const approval = approvals.find((candidate) =>
    candidate.transactionId === transaction.id &&
    candidate.agentId === transaction.agentId &&
    candidate.decisionId === transaction.decision.id &&
    candidate.decision === "WARN" &&
    candidate.policyVersion === transaction.decision.policyVersion
  );
  return approval?.status ?? "missing";
}

export function canPrepareSavedTransaction(
  transaction: SavedTransaction,
  approvalStatus: WarnApprovalStatus,
): boolean {
  if (
    transaction.status !== transaction.decision.decision ||
    transaction.decision.decision === "BLOCK" ||
    transaction.network !== "near-testnet" ||
    transaction.transactionType !== "native_transfer" ||
    transaction.asset !== "NEAR"
  ) {
    return false;
  }
  return transaction.decision.decision === "ALLOW" || approvalStatus === "approved";
}

function parseApiError(payload: unknown): { code: string | null; message: string } {
  if (
    isRecord(payload) &&
    isRecord(payload.error) &&
    typeof payload.error.message === "string"
  ) {
    return {
      code: typeof payload.error.code === "string" ? payload.error.code : null,
      message: payload.error.message,
    };
  }
  return { code: null, message: "SENTRA could not prepare this saved transaction." };
}

export class TransactionAuthorizationApiError extends Error {
  readonly code: string | null;

  constructor(
    code: string | null,
    message: string,
  ) {
    super(message);
    this.code = code;
    this.name = "TransactionAuthorizationApiError";
  }
}

function parsePreparedAuthorization(
  payload: unknown,
  now: number,
): PreparedAuthorizationResponse {
  if (!isRecord(payload) || !isRecord(payload.data)) {
    throw new Error("SENTRA returned an invalid authorization preparation response.");
  }

  const data = payload.data;
  const expiresAt = typeof data.expiresAt === "string" ? Date.parse(data.expiresAt) : Number.NaN;
  const validApproval =
    data.approval === null ||
    (isRecord(data.approval) &&
      data.approval.status === "approved" &&
      data.approval.reviewerIdentityVerified === false);

  if (
    typeof data.intentId !== "string" ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now ||
    typeof data.policyVersion !== "string" ||
    typeof data.expectedSignerAccountId !== "string" ||
    typeof data.recipient !== "string" ||
    typeof data.amountYocto !== "string" ||
    typeof data.authorizationToken !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(data.authorizationToken) ||
    data.executed !== false ||
    !validApproval
  ) {
    throw new Error("SENTRA returned malformed authorization preparation data.");
  }

  return {
    intentId: data.intentId,
    authorizationToken: data.authorizationToken,
    expiresAt: new Date(expiresAt).toISOString(),
    policyVersion: data.policyVersion,
    expectedSignerAccountId: data.expectedSignerAccountId,
    recipient: data.recipient,
    amountYocto: data.amountYocto,
    approval: data.approval === null
      ? null
      : { status: "approved", reviewerIdentityVerified: false },
    executed: false,
  };
}

export function storeTemporaryAuthorizationToken(
  ref: TemporaryTokenRef,
  prepared: PreparedAuthorizationResponse,
  transactionId: string,
  agentId: string,
  now = Date.now(),
): string | null {
  const expiresAt = Date.parse(prepared.expiresAt);
  if (
    !/^[A-Za-z0-9_-]{43}$/.test(prepared.authorizationToken) ||
    !Number.isFinite(expiresAt) ||
    expiresAt <= now
  ) {
    throw new Error("Authorization token response is invalid or expired.");
  }
  const replacedIntentId = ref.current?.intentId ?? null;
  ref.current = {
    intentId: prepared.intentId,
    transactionId,
    agentId,
    expectedSignerAccountId: prepared.expectedSignerAccountId,
    token: prepared.authorizationToken,
    expiresAt,
  };
  return replacedIntentId;
}

export function clearTemporaryAuthorizationToken(
  ref: TemporaryTokenRef,
  reason: TemporaryTokenClearReason,
): string | null {
  return takeTemporaryAuthorizationToken(ref, reason)?.intentId ?? null;
}

export function takeTemporaryAuthorizationToken(
  ref: TemporaryTokenRef,
  _reason: TemporaryTokenClearReason,
): TemporaryAuthorizationToken | null {
  const token = ref.current;
  ref.current = null;
  return token;
}

export function expireTemporaryAuthorizationToken(
  ref: TemporaryTokenRef,
  now = Date.now(),
): string | null {
  if (!ref.current || ref.current.expiresAt > now) return null;
  return clearTemporaryAuthorizationToken(ref, "expired");
}

export async function prepareSavedTransaction(
  transactionId: string,
  fetchImplementation: typeof fetch = fetch,
  now = Date.now(),
): Promise<PreparedAuthorizationResponse> {
  if (typeof transactionId !== "string" || transactionId.trim().length === 0) {
    throw new Error("A saved transaction ID is required.");
  }

  const response = await authenticatedApiFetch(
    `/api/transactions/${encodeURIComponent(transactionId)}/prepare`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: "{}",
    },
    fetchImplementation,
  );

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid authorization preparation response.");
  }

  if (!response.ok) {
    const error = parseApiError(payload);
    throw new TransactionAuthorizationApiError(error.code, error.message);
  }
  return parsePreparedAuthorization(payload, now);
}

export async function revokeAuthorizationIntent(
  intentId: string,
  authorizationToken: string,
  fetchImplementation: typeof fetch = fetch,
): Promise<{ intentId: string; status: "revoked"; revokedAt: string }> {
  if (
    typeof intentId !== "string" ||
    intentId.trim().length === 0 ||
    !/^[A-Za-z0-9_-]{43}$/.test(authorizationToken)
  ) {
    throw new Error("A valid authorization intent and temporary token are required for revocation.");
  }
  const response = await authenticatedApiFetch(
    `/api/authorization-intents/${encodeURIComponent(intentId)}/revoke`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ authorizationToken }),
    },
    fetchImplementation,
  );
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA could not confirm authorization revocation.");
  }
  if (!response.ok) {
    throw new Error("SENTRA could not confirm authorization revocation.");
  }
  if (
    !isRecord(payload) ||
    !isRecord(payload.data) ||
    payload.data.intentId !== intentId ||
    payload.data.status !== "revoked" ||
    typeof payload.data.revokedAt !== "string" ||
    !Number.isFinite(Date.parse(payload.data.revokedAt))
  ) {
    throw new Error("SENTRA returned an invalid authorization revocation response.");
  }
  return {
    intentId,
    status: "revoked",
    revokedAt: new Date(payload.data.revokedAt).toISOString(),
  };
}

export function formatYoctoNear(amountYocto: string): string | null {
  if (!/^\d+$/.test(amountYocto)) return null;
  const amount = BigInt(amountYocto);
  const whole = amount / 10n ** 24n;
  const fraction = (amount % 10n ** 24n).toString().padStart(24, "0").replace(/0+$/, "");
  return fraction.length > 0 ? `${whole}.${fraction}` : whole.toString();
}
