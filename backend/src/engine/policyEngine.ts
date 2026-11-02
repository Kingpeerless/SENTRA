import { z } from "zod";

export const DECISIONS = ["ALLOW", "WARN", "BLOCK"] as const;
export type Decision = (typeof DECISIONS)[number];

export const POLICY_RULES = [
  "INVALID_TRANSACTION",
  "INVALID_AMOUNT",
  "AGENT_NOT_FOUND",
  "AGENT_DISABLED",
  "UNSUPPORTED_NETWORK",
  "UNSUPPORTED_TRANSACTION_TYPE",
  "UNSUPPORTED_ASSET",
  "INVALID_RECIPIENT",
  "RECIPIENT_DENIED",
  "MAX_AMOUNT_EXCEEDED",
  "APPROVAL_REQUIRED",
  "INVALID_POLICY_CONFIGURATION",
  "POLICY_PASSED",
] as const;
export type PolicyRule = (typeof POLICY_RULES)[number];

export interface Agent {
  id: string;
  enabled: boolean;
}

export interface Policy {
  version: string;
  maxTransactionAmountYocto: string;
  approvalThresholdYocto: string;
  deniedRecipients: readonly string[];
}

export interface Transaction {
  agentId: string;
  network: string;
  transactionType: string;
  recipient: string;
  amountYocto: string;
  asset: string;
  reason: string;
}

export interface EvaluatedTransaction {
  agentId: string;
  network: string;
  transactionType: string;
  recipient: string;
  amountYocto: string;
  asset: string;
}

export interface PolicyDecision {
  decision: Decision;
  reasons: string[];
  triggeredRules: PolicyRule[];
  policyVersion: string | null;
  evaluatedTransaction: EvaluatedTransaction | null;
}

const YOCTO_PER_NEAR = 10n ** 24n;
const YOCTO_AMOUNT_PATTERN = /^\d+$/;
const NEAR_ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const ACCOUNT_ID_MIN_LENGTH = 2;
const ACCOUNT_ID_MAX_LENGTH = 64;

function isPositiveYoctoAmount(value: string): boolean {
  return YOCTO_AMOUNT_PATTERN.test(value) && BigInt(value) > 0n;
}

function isYoctoInteger(value: string): boolean {
  return YOCTO_AMOUNT_PATTERN.test(value);
}

function isNearAccountId(value: string): boolean {
  return (
    value.length >= ACCOUNT_ID_MIN_LENGTH &&
    value.length <= ACCOUNT_ID_MAX_LENGTH &&
    NEAR_ACCOUNT_ID_PATTERN.test(value)
  );
}

const positiveYoctoAmountSchema = z.string().refine(isPositiveYoctoAmount);
const yoctoIntegerSchema = z.string().refine(isYoctoInteger);
const accountIdSchema = z.string().refine(isNearAccountId);

const transactionSchema = z
  .object({
    agentId: z.string().min(1),
    network: z.string(),
    transactionType: z.string(),
    recipient: z.string(),
    amountYocto: z.string(),
    asset: z.string(),
    reason: z.string(),
  })
  .strict();

const policySchema = z
  .object({
    version: z.string().min(1),
    maxTransactionAmountYocto: yoctoIntegerSchema,
    approvalThresholdYocto: yoctoIntegerSchema,
    deniedRecipients: z.array(accountIdSchema),
  })
  .strict();

/**
 * Demonstration defaults: 2 NEAR requires approval, and transfers above
 * 10 NEAR are blocked. YoctoNEAR values are exact integer strings.
 */
export const DEFAULT_DEMONSTRATION_POLICY: Policy = Object.freeze({
  version: "demo-v1",
  maxTransactionAmountYocto: (10n * YOCTO_PER_NEAR).toString(),
  approvalThresholdYocto: (2n * YOCTO_PER_NEAR).toString(),
  deniedRecipients: Object.freeze([]),
});

const RULE_REASONS: Record<PolicyRule, string> = {
  INVALID_TRANSACTION: "Transaction input is invalid.",
  INVALID_AMOUNT: "Amount must be a positive integer yoctoNEAR string.",
  AGENT_NOT_FOUND: "The transaction agent is unknown.",
  AGENT_DISABLED: "The transaction agent is disabled.",
  UNSUPPORTED_NETWORK: "The requested network is not supported.",
  UNSUPPORTED_TRANSACTION_TYPE: "The transaction type is not supported.",
  UNSUPPORTED_ASSET: "The requested asset is not supported.",
  INVALID_RECIPIENT: "The recipient is not a valid NEAR account ID.",
  RECIPIENT_DENIED: "The recipient is denied by policy.",
  MAX_AMOUNT_EXCEEDED: "The transaction amount exceeds the policy maximum.",
  APPROVAL_REQUIRED: "The transaction amount requires human approval.",
  INVALID_POLICY_CONFIGURATION: "The policy configuration is invalid.",
  POLICY_PASSED: "The transaction passed all configured policy checks.",
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Evaluates a proposed transfer without side effects. Monetary comparisons
 * use bigint exclusively; free-form transaction reasons are never echoed.
 */
export function evaluateTransaction(
  input: unknown,
  agent: Agent | undefined,
  policy: Policy = DEFAULT_DEMONSTRATION_POLICY,
): PolicyDecision {
  const parsedTransaction = transactionSchema.safeParse(input);
  const parsedPolicy = policySchema.safeParse(policy);
  const policyVersion =
    isRecord(policy) && typeof policy.version === "string" ? policy.version : null;

  const triggeredRules: PolicyRule[] = [];
  const addRule = (rule: PolicyRule) => {
    if (!triggeredRules.includes(rule)) {
      triggeredRules.push(rule);
    }
  };

  if (!parsedTransaction.success) {
    addRule("INVALID_TRANSACTION");
  }

  if (!parsedPolicy.success) {
    addRule("INVALID_POLICY_CONFIGURATION");
  }

  let evaluatedTransaction: EvaluatedTransaction | null = null;
  let amount: bigint | null = null;
  let amountIsValid = false;

  if (parsedTransaction.success) {
    const transaction = parsedTransaction.data;

    if (!isPositiveYoctoAmount(transaction.amountYocto)) {
      addRule("INVALID_TRANSACTION");
      addRule("INVALID_AMOUNT");
    } else {
      amountIsValid = true;
      amount = BigInt(transaction.amountYocto);
    }

    if (transaction.network !== "near-testnet") {
      addRule("UNSUPPORTED_NETWORK");
    }
    if (transaction.transactionType !== "native_transfer") {
      addRule("UNSUPPORTED_TRANSACTION_TYPE");
    }
    if (transaction.asset !== "NEAR") {
      addRule("UNSUPPORTED_ASSET");
    }

    const recipientIsValid = isNearAccountId(transaction.recipient);
    if (!recipientIsValid) {
      addRule("INVALID_RECIPIENT");
    }

    if (
      amountIsValid &&
      recipientIsValid &&
      transaction.network === "near-testnet" &&
      transaction.transactionType === "native_transfer" &&
      transaction.asset === "NEAR"
    ) {
      evaluatedTransaction = {
        agentId: transaction.agentId,
        network: transaction.network,
        transactionType: transaction.transactionType,
        recipient: transaction.recipient,
        amountYocto: transaction.amountYocto,
        asset: transaction.asset,
      };
    }

    if (!isRecord(agent) || typeof agent.id !== "string" || agent.id !== transaction.agentId) {
      addRule("AGENT_NOT_FOUND");
    } else if (agent.enabled !== true) {
      addRule("AGENT_DISABLED");
    }

    if (
      isNearAccountId(transaction.recipient) &&
      parsedPolicy.success &&
      parsedPolicy.data.deniedRecipients.includes(transaction.recipient)
    ) {
      addRule("RECIPIENT_DENIED");
    }

    if (amountIsValid && amount !== null && parsedPolicy.success) {
      const maximum = BigInt(parsedPolicy.data.maxTransactionAmountYocto);
      const approvalThreshold = BigInt(parsedPolicy.data.approvalThresholdYocto);

      if (amount > maximum) {
        addRule("MAX_AMOUNT_EXCEEDED");
      } else if (amount >= approvalThreshold) {
        addRule("APPROVAL_REQUIRED");
      }
    }
  }

  const hasBlockRule = triggeredRules.some((rule) =>
    [
      "INVALID_TRANSACTION",
      "INVALID_AMOUNT",
      "AGENT_NOT_FOUND",
      "AGENT_DISABLED",
      "UNSUPPORTED_NETWORK",
      "UNSUPPORTED_TRANSACTION_TYPE",
      "UNSUPPORTED_ASSET",
      "INVALID_RECIPIENT",
      "RECIPIENT_DENIED",
      "MAX_AMOUNT_EXCEEDED",
      "INVALID_POLICY_CONFIGURATION",
    ].includes(rule),
  );
  const hasApprovalRule = triggeredRules.includes("APPROVAL_REQUIRED");

  let decision: Decision;
  if (hasBlockRule) {
    decision = "BLOCK";
  } else if (hasApprovalRule) {
    decision = "WARN";
  } else {
    decision = "ALLOW";
    addRule("POLICY_PASSED");
  }

  return {
    decision,
    reasons: triggeredRules.map((rule) => RULE_REASONS[rule]),
    triggeredRules,
    policyVersion,
    evaluatedTransaction,
  };
}
