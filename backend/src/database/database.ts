import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import BetterSqlite3 from "better-sqlite3";
import {
  DEFAULT_DEMONSTRATION_POLICY,
  type Agent,
  type Policy,
  type PolicyDecision,
  type Transaction,
} from "../engine/policyEngine.js";

export interface AgentRecord extends Agent {
  name: string;
  description: string;
  createdAt: string;
  updatedAt: string;
}

export interface PolicyRecord extends Policy {
  id: string;
  agentId: string;
  createdAt: string;
}

export interface TransactionRecord extends Transaction {
  id: string;
  status: PolicyDecision["decision"];
  createdAt: string;
  decision: {
    id: string;
    decision: PolicyDecision["decision"];
    reasons: string[];
    triggeredRules: string[];
    policyVersion: string;
    policySnapshot: Policy;
    createdAt: string;
  };
}

export interface ApprovalRecord {
  id: string;
  decisionId: string;
  status: "pending" | "approved" | "rejected";
  reviewedAt: string | null;
  reviewer: string | null;
  rejectionReason: string | null;
  createdAt: string;
  transactionId: string;
  agentId: string;
  decision: PolicyDecision["decision"];
  policyVersion: string;
}

export interface AuditRecord {
  id: string;
  eventType: string;
  entityType: string;
  entityId: string;
  details: Record<string, unknown>;
  createdAt: string;
}

export interface EvaluationRecord {
  transactionId: string;
  decisionId: string;
  approval: ApprovalRecord | null;
}

export interface EvaluationInput {
  agentId: string;
  transaction: Transaction;
  result: PolicyDecision;
  policy: PolicyRecord;
}

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS agents (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL CHECK (length(trim(name)) > 0),
    description TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 1 CHECK (enabled IN (0, 1)),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS policies (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    version INTEGER NOT NULL CHECK (version > 0),
    max_transaction_amount_yocto TEXT NOT NULL,
    approval_threshold_yocto TEXT NOT NULL,
    denied_recipients TEXT NOT NULL CHECK (json_valid(denied_recipients)),
    created_at TEXT NOT NULL,
    UNIQUE (agent_id, version)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    network TEXT NOT NULL,
    transaction_type TEXT NOT NULL,
    recipient TEXT NOT NULL,
    amount_yocto TEXT NOT NULL,
    asset TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('ALLOW', 'WARN', 'BLOCK')),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS decisions (
    id TEXT PRIMARY KEY,
    transaction_id TEXT NOT NULL UNIQUE REFERENCES transactions(id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK')),
    reasons TEXT NOT NULL CHECK (json_valid(reasons)),
    triggered_rules TEXT NOT NULL CHECK (json_valid(triggered_rules)),
    policy_version TEXT NOT NULL,
    policy_snapshot TEXT NOT NULL CHECK (json_valid(policy_snapshot)),
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS approvals (
    id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL UNIQUE REFERENCES decisions(id) ON DELETE RESTRICT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected')),
    reviewed_at TEXT,
    reviewer TEXT,
    rejection_reason TEXT,
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS audit_logs (
    id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    details TEXT NOT NULL CHECK (json_valid(details)),
    created_at TEXT NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_policies_agent_version
    ON policies(agent_id, version DESC);
  CREATE INDEX IF NOT EXISTS idx_transactions_agent_created
    ON transactions(agent_id, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_decisions_transaction
    ON decisions(transaction_id);
  CREATE INDEX IF NOT EXISTS idx_approvals_status_created
    ON approvals(status, created_at DESC);
  CREATE INDEX IF NOT EXISTS idx_audit_created
    ON audit_logs(created_at DESC);

  CREATE TRIGGER IF NOT EXISTS audit_logs_no_update
    BEFORE UPDATE ON audit_logs
    BEGIN
      SELECT RAISE(ABORT, 'audit logs are append-only');
    END;

  CREATE TRIGGER IF NOT EXISTS audit_logs_no_delete
    BEFORE DELETE ON audit_logs
    BEGIN
      SELECT RAISE(ABORT, 'audit logs are append-only');
    END;
`;

function now(): string {
  return new Date().toISOString();
}

function decodePolicy(row: Record<string, unknown> | undefined): PolicyRecord | undefined {
  if (!row) return undefined;
  return {
    id: String(row.id),
    agentId: String(row.agent_id),
    version: String(row.version),
    maxTransactionAmountYocto: String(row.max_transaction_amount_yocto),
    approvalThresholdYocto: String(row.approval_threshold_yocto),
    deniedRecipients: JSON.parse(String(row.denied_recipients)) as string[],
    createdAt: String(row.created_at),
  };
}

function decodeAgent(row: Record<string, unknown> | undefined): AgentRecord | undefined {
  if (!row) return undefined;
  return {
    id: String(row.id),
    name: String(row.name),
    description: String(row.description),
    enabled: Number(row.enabled) === 1,
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function decodeAudit(row: Record<string, unknown>): AuditRecord {
  return {
    id: String(row.id),
    eventType: String(row.event_type),
    entityType: String(row.entity_type),
    entityId: String(row.entity_id),
    details: JSON.parse(String(row.details)) as Record<string, unknown>,
    createdAt: String(row.created_at),
  };
}

export class SentraDatabase {
  readonly connection: BetterSqlite3.Database;

  constructor(filename = process.env.DATABASE_PATH ?? resolve(process.cwd(), "data/sentra.sqlite")) {
    if (filename !== ":memory:") {
      mkdirSync(dirname(resolve(filename)), { recursive: true });
    }

    this.connection = new BetterSqlite3(filename);
    this.connection.pragma("foreign_keys = ON");
    this.connection.pragma("journal_mode = WAL");
    this.connection.exec(SCHEMA);
  }

  close(): void {
    this.connection.close();
  }

  listAgents(): AgentRecord[] {
    const rows = this.connection
      .prepare("SELECT * FROM agents ORDER BY created_at DESC, id")
      .all() as Record<string, unknown>[];
    return rows.map((row) => decodeAgent(row)!);
  }

  getAgent(id: string): AgentRecord | undefined {
    const row = this.connection.prepare("SELECT * FROM agents WHERE id = ?").get(id) as
      | Record<string, unknown>
      | undefined;
    return decodeAgent(row);
  }

  createAgent(name: string, description: string): { agent: AgentRecord; policy: PolicyRecord } {
    const id = randomUUID();
    const policyId = randomUUID();
    const createdAt = now();
    const initialPolicy = DEFAULT_DEMONSTRATION_POLICY;
    const create = this.connection.transaction(() => {
      this.connection
        .prepare(
          `INSERT INTO agents (id, name, description, enabled, created_at, updated_at)
           VALUES (?, ?, ?, 1, ?, ?)`,
        )
        .run(id, name, description, createdAt, createdAt);
      this.insertPolicy(policyId, id, 1, initialPolicy, createdAt);
      this.insertAudit("agent.registered", "agent", id, { name, description }, createdAt);
      this.insertAudit(
        "policy.created",
        "policy",
        policyId,
        { agentId: id, version: "1", policy: initialPolicy },
        createdAt,
      );
    });
    create();
    return {
      agent: this.getAgent(id)!,
      policy: this.getCurrentPolicy(id)!,
    };
  }

  setAgentEnabled(id: string, enabled: boolean): AgentRecord | undefined {
    const update = this.connection.transaction(() => {
      const current = this.getAgent(id);
      if (!current) return undefined;
      if (current.enabled !== enabled) {
        const updatedAt = now();
        this.connection
          .prepare("UPDATE agents SET enabled = ?, updated_at = ? WHERE id = ?")
          .run(enabled ? 1 : 0, updatedAt, id);
        this.insertAudit(
          enabled ? "agent.enabled" : "agent.disabled",
          "agent",
          id,
          { enabled },
          updatedAt,
        );
      }
      return this.getAgent(id);
    });
    return update();
  }

  getCurrentPolicy(agentId: string): PolicyRecord | undefined {
    const row = this.connection
      .prepare("SELECT * FROM policies WHERE agent_id = ? ORDER BY version DESC LIMIT 1")
      .get(agentId) as Record<string, unknown> | undefined;
    return decodePolicy(row);
  }

  updatePolicy(
    agentId: string,
    policy: Omit<Policy, "version">,
  ): PolicyRecord | undefined {
    const update = this.connection.transaction(() => {
      if (!this.getAgent(agentId)) return undefined;
      const previous = this.getCurrentPolicy(agentId);
      const version = Number(previous?.version ?? "0") + 1;
      const id = randomUUID();
      const createdAt = now();
      const updated: Policy = { ...policy, version: String(version) };
      this.insertPolicy(id, agentId, version, updated, createdAt);
      this.insertAudit(
        "policy.updated",
        "policy",
        id,
        { agentId, version: updated.version, policy: updated },
        createdAt,
      );
      return this.getCurrentPolicy(agentId);
    });
    return update();
  }

  createEvaluation(input: EvaluationInput): EvaluationRecord {
    const transactionId = randomUUID();
    const decisionId = randomUUID();
    const approvalId = input.result.decision === "WARN" ? randomUUID() : null;
    const createdAt = now();
    const { transaction, result, policy } = input;

    const persist = this.connection.transaction(() => {
      this.connection
        .prepare(
          `INSERT INTO transactions
            (id, agent_id, network, transaction_type, recipient, amount_yocto, asset, reason, status, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          transactionId,
          input.agentId,
          transaction.network,
          transaction.transactionType,
          transaction.recipient,
          transaction.amountYocto,
          transaction.asset,
          transaction.reason,
          result.decision,
          createdAt,
        );

      this.connection
        .prepare(
          `INSERT INTO decisions
            (id, transaction_id, policy_id, decision, reasons, triggered_rules, policy_version, policy_snapshot, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          decisionId,
          transactionId,
          policy.id,
          result.decision,
          JSON.stringify(result.reasons),
          JSON.stringify(result.triggeredRules),
          policy.version,
          JSON.stringify({
            version: policy.version,
            maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
            approvalThresholdYocto: policy.approvalThresholdYocto,
            deniedRecipients: policy.deniedRecipients,
          }),
          createdAt,
        );

      if (approvalId) {
        this.connection
          .prepare(
            `INSERT INTO approvals
              (id, decision_id, status, reviewed_at, reviewer, rejection_reason, created_at)
             VALUES (?, ?, 'pending', NULL, NULL, NULL, ?)`,
          )
          .run(approvalId, decisionId, createdAt);
      }

      this.insertAudit(
        "transaction.evaluated",
        "transaction",
        transactionId,
        {
          decisionId,
          decision: result.decision,
          triggeredRules: result.triggeredRules,
          policyVersion: policy.version,
          policySnapshot: {
            version: policy.version,
            maxTransactionAmountYocto: policy.maxTransactionAmountYocto,
            approvalThresholdYocto: policy.approvalThresholdYocto,
            deniedRecipients: policy.deniedRecipients,
          },
        },
        createdAt,
      );
    });
    persist();
    return {
      transactionId,
      decisionId,
      approval: approvalId ? this.getApproval(approvalId) ?? null : null,
    };
  }

  listTransactions(): TransactionRecord[] {
    const rows = this.connection
      .prepare(
        `SELECT t.*, d.id AS decision_id, d.decision, d.reasons, d.triggered_rules,
                d.policy_version, d.policy_snapshot, d.created_at AS decision_created_at
         FROM transactions t JOIN decisions d ON d.transaction_id = t.id
         ORDER BY t.created_at DESC, t.id`,
      )
      .all() as Record<string, unknown>[];
    return rows.map((row) => this.decodeTransaction(row));
  }

  getTransaction(id: string): TransactionRecord | undefined {
    const row = this.connection
      .prepare(
        `SELECT t.*, d.id AS decision_id, d.decision, d.reasons, d.triggered_rules,
                d.policy_version, d.policy_snapshot, d.created_at AS decision_created_at
         FROM transactions t JOIN decisions d ON d.transaction_id = t.id
         WHERE t.id = ?`,
      )
      .get(id) as Record<string, unknown> | undefined;
    return row ? this.decodeTransaction(row) : undefined;
  }

  listApprovals(): ApprovalRecord[] {
    const rows = this.connection
      .prepare(
        `SELECT a.*, d.transaction_id, d.decision, d.policy_version, t.agent_id
         FROM approvals a
         JOIN decisions d ON d.id = a.decision_id
         JOIN transactions t ON t.id = d.transaction_id
         ORDER BY a.created_at DESC, a.id`,
      )
      .all() as Record<string, unknown>[];
    return rows.map((row) => this.decodeApproval(row));
  }

  getApproval(id: string): ApprovalRecord | undefined {
    const row = this.connection
      .prepare(
        `SELECT a.*, d.transaction_id, d.decision, d.policy_version, t.agent_id
         FROM approvals a
         JOIN decisions d ON d.id = a.decision_id
         JOIN transactions t ON t.id = d.transaction_id
         WHERE a.id = ?`,
      )
      .get(id) as Record<string, unknown> | undefined;
    return row ? this.decodeApproval(row) : undefined;
  }

  reviewApproval(
    id: string,
    status: "approved" | "rejected",
    reviewer: string,
    rejectionReason?: string,
  ): ApprovalRecord | undefined {
    const review = this.connection.transaction(() => {
      const approval = this.getApproval(id);
      if (!approval) return undefined;
      if (approval.status !== "pending" || approval.decision !== "WARN") {
        return approval;
      }

      const reviewedAt = now();
      const result = this.connection
        .prepare(
          `UPDATE approvals
           SET status = ?, reviewed_at = ?, reviewer = ?, rejection_reason = ?
           WHERE id = ? AND status = 'pending'`,
        )
        .run(status, reviewedAt, reviewer, rejectionReason ?? null, id);
      if (result.changes === 1) {
        this.insertAudit(
          status === "approved" ? "approval.granted" : "approval.rejected",
          "approval",
          id,
          {
            decisionId: approval.decisionId,
            transactionId: approval.transactionId,
            reviewer,
            rejectionReason: rejectionReason ?? null,
            status,
          },
          reviewedAt,
        );
      }
      return this.getApproval(id);
    });
    return review();
  }

  listAudit(): AuditRecord[] {
    const rows = this.connection
      .prepare("SELECT * FROM audit_logs ORDER BY created_at DESC, id")
      .all() as Record<string, unknown>[];
    return rows.map(decodeAudit);
  }

  private insertPolicy(
    id: string,
    agentId: string,
    version: number,
    policy: Policy,
    createdAt: string,
  ): void {
    this.connection
      .prepare(
        `INSERT INTO policies
          (id, agent_id, version, max_transaction_amount_yocto, approval_threshold_yocto, denied_recipients, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        id,
        agentId,
        version,
        policy.maxTransactionAmountYocto,
        policy.approvalThresholdYocto,
        JSON.stringify(policy.deniedRecipients),
        createdAt,
      );
  }

  private insertAudit(
    eventType: string,
    entityType: string,
    entityId: string,
    details: Record<string, unknown>,
    createdAt: string,
  ): void {
    this.connection
      .prepare(
        `INSERT INTO audit_logs (id, event_type, entity_type, entity_id, details, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
      )
      .run(randomUUID(), eventType, entityType, entityId, JSON.stringify(details), createdAt);
  }

  private decodeTransaction(row: Record<string, unknown>): TransactionRecord {
    return {
      id: String(row.id),
      agentId: String(row.agent_id),
      network: String(row.network),
      transactionType: String(row.transaction_type),
      recipient: String(row.recipient),
      amountYocto: String(row.amount_yocto),
      asset: String(row.asset),
      reason: String(row.reason),
      status: row.status as PolicyDecision["decision"],
      createdAt: String(row.created_at),
      decision: {
        id: String(row.decision_id),
        decision: row.decision as PolicyDecision["decision"],
        reasons: JSON.parse(String(row.reasons)) as string[],
        triggeredRules: JSON.parse(String(row.triggered_rules)) as string[],
        policyVersion: String(row.policy_version),
        policySnapshot: JSON.parse(String(row.policy_snapshot)) as Policy,
        createdAt: String(row.decision_created_at),
      },
    };
  }

  private decodeApproval(row: Record<string, unknown>): ApprovalRecord {
    return {
      id: String(row.id),
      decisionId: String(row.decision_id),
      status: row.status as ApprovalRecord["status"],
      reviewedAt: row.reviewed_at === null ? null : String(row.reviewed_at),
      reviewer: row.reviewer === null ? null : String(row.reviewer),
      rejectionReason:
        row.rejection_reason === null ? null : String(row.rejection_reason),
      createdAt: String(row.created_at),
      transactionId: String(row.transaction_id),
      agentId: String(row.agent_id ?? ""),
      decision: row.decision as PolicyDecision["decision"],
      policyVersion: String(row.policy_version),
    };
  }
}
