import {
  evaluateTransaction,
  type Policy,
  type PolicyDecision,
  type Transaction,
} from "../engine/policyEngine.js";
import {
  SentraDatabase,
  type AgentRecord,
  type ApprovalRecord,
  type AuditRecord,
  type PolicyRecord,
  type TransactionRecord,
} from "../database/database.js";

export class ServiceError extends Error {
  constructor(
    readonly statusCode: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ServiceError";
  }
}

export class SentraService {
  constructor(private readonly database: SentraDatabase) {}

  listAgents(): AgentRecord[] {
    return this.database.listAgents();
  }

  getAgent(id: string): AgentRecord {
    const agent = this.database.getAgent(id);
    if (!agent) throw new ServiceError(404, "NOT_FOUND", "Agent not found.");
    return agent;
  }

  registerAgent(name: string, description: string) {
    return this.database.createAgent(name, description);
  }

  setAgentEnabled(id: string, enabled: boolean): AgentRecord {
    const agent = this.database.setAgentEnabled(id, enabled);
    if (!agent) throw new ServiceError(404, "NOT_FOUND", "Agent not found.");
    return agent;
  }

  getPolicy(agentId: string): PolicyRecord {
    this.getAgent(agentId);
    const policy = this.database.getCurrentPolicy(agentId);
    if (!policy) throw new ServiceError(500, "INTERNAL_ERROR", "Agent policy is unavailable.");
    return policy;
  }

  updatePolicy(
    agentId: string,
    policy: Omit<Policy, "version">,
  ): PolicyRecord {
    const updated = this.database.updatePolicy(agentId, policy);
    if (!updated) throw new ServiceError(404, "NOT_FOUND", "Agent not found.");
    return updated;
  }

  evaluate(agentId: string, proposal: Omit<Transaction, "agentId"> & { agentId?: string }) {
    const agent = this.getAgent(agentId);
    if (proposal.agentId !== undefined && proposal.agentId !== agent.id) {
      throw new ServiceError(400, "INVALID_INPUT", "Transaction agentId must match the requested agent.");
    }

    const policyRecord = this.getPolicy(agent.id);
    const transaction: Transaction = { ...proposal, agentId: agent.id };
    const policy: Policy = {
      version: policyRecord.version,
      maxTransactionAmountYocto: policyRecord.maxTransactionAmountYocto,
      approvalThresholdYocto: policyRecord.approvalThresholdYocto,
      deniedRecipients: policyRecord.deniedRecipients,
    };
    const decision: PolicyDecision = evaluateTransaction(
      transaction,
      { id: agent.id, enabled: agent.enabled },
      policy,
    );
    const persisted = this.database.createEvaluation({
      agentId: agent.id,
      transaction,
      result: decision,
      policy: policyRecord,
    });

    return {
      transactionId: persisted.transactionId,
      decisionId: persisted.decisionId,
      ...decision,
      approval: persisted.approval,
      executed: false,
    };
  }

  listTransactions(): TransactionRecord[] {
    return this.database.listTransactions();
  }

  getTransaction(id: string): TransactionRecord {
    const transaction = this.database.getTransaction(id);
    if (!transaction) throw new ServiceError(404, "NOT_FOUND", "Transaction not found.");
    return transaction;
  }

  listApprovals(): ApprovalRecord[] {
    return this.database.listApprovals();
  }

  getApproval(id: string): ApprovalRecord {
    const approval = this.database.getApproval(id);
    if (!approval) throw new ServiceError(404, "NOT_FOUND", "Approval not found.");
    return approval;
  }

  reviewApproval(
    id: string,
    status: "approved" | "rejected",
    reviewer: string,
    rejectionReason?: string,
  ): ApprovalRecord {
    const existing = this.getApproval(id);
    if (existing.status !== "pending") {
      throw new ServiceError(409, "CONFLICT", "Approval has already been reviewed.");
    }
    if (existing.decision !== "WARN") {
      throw new ServiceError(409, "CONFLICT", "Only pending WARN decisions can be reviewed.");
    }
    const agent = this.getAgent(existing.agentId);
    if (!agent.enabled) {
      throw new ServiceError(409, "CONFLICT", "Disabled agents require transaction re-evaluation.");
    }
    const currentPolicy = this.getPolicy(existing.agentId);
    if (existing.policyVersion !== currentPolicy.version) {
      throw new ServiceError(409, "CONFLICT", "Policy changed; transaction re-evaluation is required.");
    }

    const approval = this.database.reviewApproval(id, status, reviewer, rejectionReason);
    if (!approval) throw new ServiceError(404, "NOT_FOUND", "Approval not found.");
    if (approval.status !== status) {
      throw new ServiceError(409, "CONFLICT", "Approval state changed before review.");
    }
    return approval;
  }

  listAudit(): AuditRecord[] {
    return this.database.listAudit();
  }
}
