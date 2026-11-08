import {
  parseApprovalsResponse,
  parseTransactionsResponse,
  type SavedApproval,
  type SavedTransaction,
  type TransactionDecision,
} from "./transactionAuthorization.ts";
import { authenticatedApiFetch } from "./apiAccess.ts";

const ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const YOCTO_PER_NEAR = 10n ** 24n;

export interface TransactionEvaluation {
  transactionId: string;
  decisionId: string;
  decision: TransactionDecision;
  reasons: string[];
  triggeredRules: string[];
  policyVersion: string | null;
  approval: {
    id: string;
    status: "pending" | "approved" | "rejected";
  } | null;
  executed: false;
}

export interface TransactionReviewData {
  transactions: SavedTransaction[];
  approvals: SavedApproval[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDecision(value: unknown): value is TransactionDecision {
  return value === "ALLOW" || value === "WARN" || value === "BLOCK";
}

export function nearToYocto(amountNear: string): string {
  const normalized = amountNear.trim();
  const match = /^(0|[1-9]\d*)(?:\.(\d{1,24}))?$/.exec(normalized);
  if (!match) {
    throw new Error("Enter a positive NEAR amount with no more than 24 decimal places.");
  }
  const whole = BigInt(match[1]);
  const fraction = BigInt((match[2] ?? "").padEnd(24, "0") || "0");
  const amount = whole * YOCTO_PER_NEAR + fraction;
  if (amount <= 0n) {
    throw new Error("Transaction amount must be greater than zero.");
  }
  return amount.toString();
}

export function validateRecipient(accountId: string): string {
  const normalized = accountId.trim();
  if (
    normalized.length < 2 ||
    normalized.length > 64 ||
    !ACCOUNT_ID_PATTERN.test(normalized)
  ) {
    throw new Error("Enter a valid NEAR account ID (2–64 lowercase letters, digits, or . _ -).");
  }
  return normalized;
}

function parseEvaluation(payload: unknown): TransactionEvaluation {
  if (
    !isRecord(payload) ||
    !isRecord(payload.data) ||
    typeof payload.data.transactionId !== "string" ||
    typeof payload.data.decisionId !== "string" ||
    !isDecision(payload.data.decision) ||
    typeof payload.data.executed !== "boolean" ||
    payload.data.executed !== false ||
    (payload.data.policyVersion !== null && typeof payload.data.policyVersion !== "string")
  ) {
    throw new Error("SENTRA returned malformed transaction evaluation data.");
  }

  const approval = payload.data.approval;
  if (
    approval !== null &&
    (!isRecord(approval) ||
      typeof approval.id !== "string" ||
      !["pending", "approved", "rejected"].includes(String(approval.status)))
  ) {
    throw new Error("SENTRA returned malformed transaction approval data.");
  }
  if (payload.data.decision === "WARN" && approval === null) {
    throw new Error("SENTRA returned a WARN decision without its required approval record.");
  }
  if (payload.data.decision !== "WARN" && approval !== null) {
    throw new Error("SENTRA returned an unexpected approval for this decision.");
  }

  return {
    transactionId: payload.data.transactionId,
    decisionId: payload.data.decisionId,
    decision: payload.data.decision,
    reasons: parseStringArray(payload.data.reasons, "evaluation reasons"),
    triggeredRules: parseStringArray(payload.data.triggeredRules, "triggered policy rules"),
    policyVersion: payload.data.policyVersion,
    approval: approval === null
      ? null
      : {
          id: approval.id as string,
          status: approval.status as "pending" | "approved" | "rejected",
        },
    executed: false,
  };
}

function parseStringArray(value: unknown, description: string): string[] {
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`SENTRA returned malformed ${description}.`);
  }
  return value;
}

function apiError(payload: unknown): string {
  return isRecord(payload) &&
      isRecord(payload.error) &&
      typeof payload.error.message === "string"
    ? payload.error.message
    : "SENTRA could not evaluate this transaction.";
}

export async function submitTransactionEvaluation(
  input: {
    agentId: string;
    recipient: string;
    amountNear: string;
  },
  fetchImplementation: typeof fetch = fetch,
): Promise<TransactionEvaluation> {
  if (typeof input.agentId !== "string" || input.agentId.trim().length === 0) {
    throw new Error("Select an enabled agent.");
  }
  const recipient = validateRecipient(input.recipient);
  const amountYocto = nearToYocto(input.amountNear);
  const response = await authenticatedApiFetch("/api/transactions/evaluate", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({
      agentId: input.agentId,
      transaction: {
        network: "near-testnet",
        transactionType: "native_transfer",
        recipient,
        amountYocto,
        asset: "NEAR",
        reason: "Operator-submitted transaction evaluation",
      },
    }),
  }, fetchImplementation);

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid transaction evaluation response.");
  }
  if (!response.ok) throw new Error(apiError(payload));
  return parseEvaluation(payload);
}

export async function loadTransactionReviewData(
  fetchImplementation: typeof fetch = fetch,
): Promise<TransactionReviewData> {
  const [transactionsResponse, approvalsResponse] = await Promise.all([
    authenticatedApiFetch("/api/transactions", {
      method: "GET",
      headers: { accept: "application/json" },
      cache: "no-store",
    }, fetchImplementation),
    authenticatedApiFetch("/api/approvals", {
      method: "GET",
      headers: { accept: "application/json" },
      cache: "no-store",
    }, fetchImplementation),
  ]);
  if (!transactionsResponse.ok || !approvalsResponse.ok) {
    throw new Error("SENTRA could not load saved transactions and approval records.");
  }
  const [transactionsPayload, approvalsPayload] = await Promise.all([
    transactionsResponse.json(),
    approvalsResponse.json(),
  ]);
  return {
    transactions: parseTransactionsResponse(transactionsPayload),
    approvals: parseApprovalsResponse(approvalsPayload),
  };
}
