import type {
  SavedApproval,
  SavedTransaction,
} from "./transactionAuthorization.ts";
import { authenticatedApiFetch } from "./apiAccess.ts";

export interface PendingWarnApproval {
  approval: SavedApproval;
  transaction: SavedTransaction;
}

export type ApprovalReviewAction = "approve" | "reject";

const LOCAL_DEMO_REVIEWER = "Local demo reviewer (unverified)";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function getPendingWarnApprovals(
  approvals: readonly SavedApproval[],
  transactions: readonly SavedTransaction[],
): PendingWarnApproval[] {
  const pending: PendingWarnApproval[] = [];
  for (const approval of approvals) {
    if (approval.status !== "pending" || approval.decision !== "WARN") continue;
    const transaction = transactions.find((candidate) =>
      candidate.id === approval.transactionId &&
      candidate.agentId === approval.agentId &&
      candidate.status === "WARN" &&
      candidate.decision.decision === "WARN" &&
      candidate.decision.id === approval.decisionId &&
      candidate.decision.policyVersion === approval.policyVersion
    );
    if (transaction) pending.push({ approval, transaction });
  }
  return pending;
}

export async function reviewWarnApproval(
  approval: SavedApproval,
  transaction: SavedTransaction,
  action: ApprovalReviewAction,
  rejectionReason = "",
  fetchImplementation: typeof fetch = fetch,
): Promise<SavedApproval> {
  const isMatchingPendingWarn =
    approval.status === "pending" &&
    approval.decision === "WARN" &&
    transaction.status === "WARN" &&
    transaction.decision.decision === "WARN" &&
    approval.transactionId === transaction.id &&
    approval.agentId === transaction.agentId &&
    approval.decisionId === transaction.decision.id &&
    approval.policyVersion === transaction.decision.policyVersion;
  if (!isMatchingPendingWarn) {
    throw new Error("Only a pending WARN approval matching its saved transaction can be reviewed.");
  }
  if (action !== "approve" && action !== "reject") {
    throw new Error("Unsupported approval action.");
  }
  if (action === "reject" && rejectionReason.trim().length === 0) {
    throw new Error("Enter a reason before rejecting this WARN approval.");
  }

  const response = await authenticatedApiFetch(
    `/api/approvals/${encodeURIComponent(approval.id)}/${action}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify(
        action === "approve"
          ? { reviewer: LOCAL_DEMO_REVIEWER }
          : {
              reviewer: LOCAL_DEMO_REVIEWER,
              rejectionReason: rejectionReason.trim(),
            },
      ),
    },
    fetchImplementation,
  );

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid approval review response.");
  }
  if (!response.ok) {
    const message = isRecord(payload) &&
        isRecord(payload.error) &&
        typeof payload.error.message === "string"
      ? payload.error.message
      : "SENTRA could not update this approval.";
    throw new Error(message);
  }

  const expectedStatus = action === "approve" ? "approved" : "rejected";
  if (
    !isRecord(payload) ||
    !isRecord(payload.data) ||
    payload.data.id !== approval.id ||
    payload.data.status !== expectedStatus ||
    payload.data.decision !== "WARN"
  ) {
    throw new Error("SENTRA returned an invalid approval review result.");
  }
  return { ...approval, status: expectedStatus };
}
