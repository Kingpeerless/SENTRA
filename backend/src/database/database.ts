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
  authorizedNearAccountId: string | null;
  createdAt: string;
  updatedAt: string;
}

export const AUTHORIZATION_INTENT_STATES = [
  "issued",
  "verifying",
  "verified",
  "failed",
  "indeterminate",
  "expired",
  "stale",
  "revoked",
] as const;
export type AuthorizationIntentState = (typeof AUTHORIZATION_INTENT_STATES)[number];

export interface AuthorizationIntentRecord {
  id: string;
  transactionId: string;
  decisionId: string;
  approvalId: string | null;
  tokenHash: string;
  policyId: string;
  policyVersion: string;
  authorizedWalletAccountId: string;
  expiresAt: string;
  createdAt: string;
  state: AuthorizationIntentState;
  transactionHash: string | null;
  claimedSignerAccountId: string | null;
  consumedAt: string | null;
}

export interface NewAuthorizationIntent {
  transactionId: string;
  decisionId: string;
  approvalId: string | null;
  tokenHash: string;
  policyId: string;
  policyVersion: string;
  authorizedWalletAccountId: string;
  expiresAt: string;
}

export interface ChainVerificationRecord {
  id: string;
  authorizationIntentId: string;
  transactionHash: string;
  status: "verified" | "failed" | "unverified";
  reason: string;
  observedSignerAccountId: string | null;
  observedReceiverAccountId: string | null;
  observedAmountYocto: string | null;
  createdAt: string;
  verifiedAt: string;
}

export interface NewChainVerification {
  authorizationIntentId: string;
  transactionHash: string;
  status: ChainVerificationRecord["status"];
  reason: string;
  observedSignerAccountId: string | null;
  observedReceiverAccountId: string | null;
  observedAmountYocto: string | null;
  verifiedAt: string;
}

export interface CompletedChainVerification extends ChainVerificationRecord {
  authorizationIntentState: AuthorizationIntentState;
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

export interface ThreatSimulationRecord {
  id: string;
  agentId: string;
  policyId: string;
  scenarioId: string;
  description: string;
  maliciousInstruction: string;
  simulatedResponse: string;
  proposedTransaction: Transaction;
  checksPerformed: string[];
  decision: PolicyDecision["decision"];
  explanation: string;
  triggeredPolicyRules: string[];
  outcome: "blocked" | "warned" | "allowed";
  isSimulation: true;
  executed: false;
  policyVersion: string;
  createdAt: string;
}

export type NewThreatSimulation = Omit<ThreatSimulationRecord, "id" | "createdAt">;

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

  CREATE TABLE IF NOT EXISTS threat_simulations (
    id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL REFERENCES agents(id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
    scenario_id TEXT NOT NULL,
    description TEXT NOT NULL,
    malicious_instruction TEXT NOT NULL,
    simulated_response TEXT NOT NULL,
    proposed_transaction TEXT NOT NULL CHECK (json_valid(proposed_transaction)),
    checks_performed TEXT NOT NULL CHECK (json_valid(checks_performed)),
    decision TEXT NOT NULL CHECK (decision IN ('ALLOW', 'WARN', 'BLOCK')),
    explanation TEXT NOT NULL,
    triggered_policy_rules TEXT NOT NULL CHECK (json_valid(triggered_policy_rules)),
    outcome TEXT NOT NULL CHECK (outcome IN ('blocked', 'warned', 'allowed')),
    is_simulation INTEGER NOT NULL DEFAULT 1 CHECK (is_simulation = 1),
    executed INTEGER NOT NULL DEFAULT 0 CHECK (executed = 0),
    policy_version TEXT NOT NULL,
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
  CREATE INDEX IF NOT EXISTS idx_threat_simulations_agent_created
    ON threat_simulations(agent_id, created_at DESC);

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

const LATEST_SCHEMA_VERSION = 4;
const NEAR_ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const NEAR_TRANSACTION_HASH_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;

function now(): string {
  return new Date().toISOString();
}

export function isValidNearAccountId(value: string): boolean {
  return value.length >= 2 && value.length <= 64 && NEAR_ACCOUNT_ID_PATTERN.test(value);
}

export function isValidNearTransactionHash(value: string): boolean {
  return NEAR_TRANSACTION_HASH_PATTERN.test(value);
}

function decodeAuthorizationIntent(
  row: Record<string, unknown> | undefined,
): AuthorizationIntentRecord | undefined {
  if (!row) return undefined;
  return {
    id: String(row.id),
    transactionId: String(row.transaction_id),
    decisionId: String(row.decision_id),
    approvalId: row.approval_id === null ? null : String(row.approval_id),
    tokenHash: String(row.token_hash),
    policyId: String(row.policy_id),
    policyVersion: String(row.policy_version),
    authorizedWalletAccountId: String(row.authorized_wallet_account_id),
    expiresAt: String(row.expires_at),
    createdAt: String(row.created_at),
    state: row.state as AuthorizationIntentState,
    transactionHash: row.transaction_hash === null ? null : String(row.transaction_hash),
    claimedSignerAccountId:
      row.claimed_signer_account_id === null
        ? null
        : String(row.claimed_signer_account_id),
    consumedAt: row.consumed_at === null ? null : String(row.consumed_at),
  };
}

function decodeChainVerification(
  row: Record<string, unknown> | undefined,
): ChainVerificationRecord | undefined {
  if (!row) return undefined;
  return {
    id: String(row.id),
    authorizationIntentId: String(row.authorization_intent_id),
    transactionHash: String(row.transaction_hash),
    status: row.status as ChainVerificationRecord["status"],
    reason: String(row.reason),
    observedSignerAccountId:
      row.observed_signer_account_id === null
        ? null
        : String(row.observed_signer_account_id),
    observedReceiverAccountId:
      row.observed_receiver_account_id === null
        ? null
        : String(row.observed_receiver_account_id),
    observedAmountYocto:
      row.observed_amount_yocto === null ? null : String(row.observed_amount_yocto),
    createdAt: String(row.created_at),
    verifiedAt: String(row.verified_at),
  };
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
    authorizedNearAccountId:
      row.authorized_near_account_id === null || row.authorized_near_account_id === undefined
        ? null
        : String(row.authorized_near_account_id),
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
    this.migrate();
  }

  close(): void {
    this.connection.close();
  }

  private migrate(): void {
    const version = this.connection.pragma("user_version", { simple: true }) as number;
    if (version > LATEST_SCHEMA_VERSION) {
      throw new Error(`Database schema version ${version} is newer than supported.`);
    }

    if (version < 1) {
      const migration = this.connection.transaction(() => {
        this.connection.exec(`
          ALTER TABLE agents ADD COLUMN authorized_near_account_id TEXT
            CHECK (
              authorized_near_account_id IS NULL OR (
                length(authorized_near_account_id) BETWEEN 2 AND 64
                AND authorized_near_account_id = lower(authorized_near_account_id)
                AND authorized_near_account_id NOT GLOB '*[^a-z0-9._-]*'
              )
            );
          CREATE UNIQUE INDEX idx_agents_authorized_near_account
            ON agents(authorized_near_account_id)
            WHERE authorized_near_account_id IS NOT NULL;

          CREATE TABLE authorization_intents (
            id TEXT PRIMARY KEY,
            transaction_id TEXT NOT NULL REFERENCES transactions(id) ON DELETE RESTRICT,
            decision_id TEXT NOT NULL REFERENCES decisions(id) ON DELETE RESTRICT,
            approval_id TEXT UNIQUE REFERENCES approvals(id) ON DELETE RESTRICT,
            token_hash TEXT NOT NULL UNIQUE
              CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
            policy_id TEXT NOT NULL REFERENCES policies(id) ON DELETE RESTRICT,
            policy_version TEXT NOT NULL,
            authorized_wallet_account_id TEXT NOT NULL
              CHECK (
                length(authorized_wallet_account_id) BETWEEN 2 AND 64
                AND authorized_wallet_account_id = lower(authorized_wallet_account_id)
                AND authorized_wallet_account_id NOT GLOB '*[^a-z0-9._-]*'
              ),
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            state TEXT NOT NULL CHECK (
              state IN ('issued', 'verifying', 'verified', 'failed', 'indeterminate', 'expired', 'stale')
            ),
            transaction_hash TEXT,
            claimed_signer_account_id TEXT,
            consumed_at TEXT,
            CHECK (
              (transaction_hash IS NULL AND claimed_signer_account_id IS NULL)
              OR (transaction_hash IS NOT NULL AND claimed_signer_account_id IS NOT NULL)
            ),
            CHECK (
              state != 'verifying'
              OR (transaction_hash IS NOT NULL AND claimed_signer_account_id IS NOT NULL)
            ),
            CHECK (
              state NOT IN ('verified', 'failed', 'expired', 'stale')
              OR consumed_at IS NOT NULL
            )
          );

          CREATE INDEX idx_authorization_intents_transaction
            ON authorization_intents(transaction_id, created_at DESC);
          CREATE INDEX idx_authorization_intents_state_expiry
            ON authorization_intents(state, expires_at);

          CREATE TABLE chain_verifications (
            id TEXT PRIMARY KEY,
            authorization_intent_id TEXT NOT NULL
              REFERENCES authorization_intents(id) ON DELETE RESTRICT,
            transaction_hash TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK (status IN ('verified', 'failed', 'unverified')),
            reason TEXT NOT NULL,
            observed_signer_account_id TEXT,
            observed_receiver_account_id TEXT,
            observed_amount_yocto TEXT
              CHECK (
                observed_amount_yocto IS NULL OR (
                  length(observed_amount_yocto) > 0
                  AND observed_amount_yocto NOT GLOB '*[^0-9]*'
                )
              ),
            created_at TEXT NOT NULL,
            verified_at TEXT NOT NULL
          );

          CREATE INDEX idx_chain_verifications_intent
            ON chain_verifications(authorization_intent_id, created_at DESC);

          CREATE TRIGGER authorization_intents_validate_insert
            BEFORE INSERT ON authorization_intents
            BEGIN
              SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM transactions t
                JOIN decisions d ON d.id = NEW.decision_id AND d.transaction_id = t.id
                JOIN policies p ON p.id = NEW.policy_id
                  AND p.agent_id = t.agent_id
                  AND CAST(p.version AS TEXT) = NEW.policy_version
                JOIN agents a ON a.id = t.agent_id
                  AND a.authorized_near_account_id = NEW.authorized_wallet_account_id
                WHERE t.id = NEW.transaction_id
                  AND d.policy_id = NEW.policy_id
                  AND d.policy_version = NEW.policy_version
                  AND d.decision IN ('ALLOW', 'WARN')
                  AND a.enabled = 1
                  AND p.version = (
                    SELECT MAX(current_policy.version)
                    FROM policies current_policy
                    WHERE current_policy.agent_id = p.agent_id
                  )
                  AND (
                    (d.decision = 'ALLOW' AND NEW.approval_id IS NULL)
                    OR (
                      d.decision = 'WARN'
                      AND EXISTS (
                        SELECT 1 FROM approvals ap
                        WHERE ap.id = NEW.approval_id
                          AND ap.decision_id = d.id
                          AND ap.status = 'approved'
                      )
                    )
                  )
              ) THEN RAISE(ABORT, 'authorization intent does not match eligible records') END;
            END;

          CREATE TRIGGER authorization_intents_validate_transition
            BEFORE UPDATE OF state ON authorization_intents
            WHEN NOT (
              (OLD.state = 'issued' AND NEW.state IN ('verifying', 'expired', 'stale'))
              OR (OLD.state = 'indeterminate' AND NEW.state IN ('verifying', 'expired', 'stale'))
              OR (
                OLD.state = 'verifying'
                AND NEW.state IN ('verified', 'failed', 'indeterminate', 'stale')
              )
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorization intent state transition');
            END;

          CREATE TRIGGER authorization_intents_protect_snapshot
            BEFORE UPDATE OF transaction_id, decision_id, approval_id, token_hash,
              policy_id, policy_version, authorized_wallet_account_id, expires_at, created_at
            ON authorization_intents
            BEGIN
              SELECT RAISE(ABORT, 'authorization intent snapshot is immutable');
            END;
        `);
        this.connection.pragma("user_version = 1");
      });
      migration.immediate();
    }

    if (version < 2) {
      const migration = this.connection.transaction(() => {
        this.connection.exec(`
          CREATE TRIGGER agents_validate_near_account_insert
            BEFORE INSERT ON agents
            WHEN NEW.authorized_near_account_id IS NOT NULL AND NOT (
              length(NEW.authorized_near_account_id) BETWEEN 2 AND 64
              AND NEW.authorized_near_account_id = lower(NEW.authorized_near_account_id)
              AND substr(NEW.authorized_near_account_id, 1, 1) GLOB '[a-z0-9]'
              AND substr(NEW.authorized_near_account_id, -1, 1) GLOB '[a-z0-9]'
              AND NEW.authorized_near_account_id NOT GLOB '*[^a-z0-9._-]*'
              AND instr(NEW.authorized_near_account_id, '..') = 0
              AND instr(NEW.authorized_near_account_id, '._') = 0
              AND instr(NEW.authorized_near_account_id, '.-') = 0
              AND instr(NEW.authorized_near_account_id, '_.') = 0
              AND instr(NEW.authorized_near_account_id, '__') = 0
              AND instr(NEW.authorized_near_account_id, '_-') = 0
              AND instr(NEW.authorized_near_account_id, '-.') = 0
              AND instr(NEW.authorized_near_account_id, '-_') = 0
              AND instr(NEW.authorized_near_account_id, '--') = 0
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorized NEAR account ID');
            END;

          CREATE TRIGGER agents_validate_near_account_update
            BEFORE UPDATE OF authorized_near_account_id ON agents
            WHEN NEW.authorized_near_account_id IS NOT NULL AND NOT (
              length(NEW.authorized_near_account_id) BETWEEN 2 AND 64
              AND NEW.authorized_near_account_id = lower(NEW.authorized_near_account_id)
              AND substr(NEW.authorized_near_account_id, 1, 1) GLOB '[a-z0-9]'
              AND substr(NEW.authorized_near_account_id, -1, 1) GLOB '[a-z0-9]'
              AND NEW.authorized_near_account_id NOT GLOB '*[^a-z0-9._-]*'
              AND instr(NEW.authorized_near_account_id, '..') = 0
              AND instr(NEW.authorized_near_account_id, '._') = 0
              AND instr(NEW.authorized_near_account_id, '.-') = 0
              AND instr(NEW.authorized_near_account_id, '_.') = 0
              AND instr(NEW.authorized_near_account_id, '__') = 0
              AND instr(NEW.authorized_near_account_id, '_-') = 0
              AND instr(NEW.authorized_near_account_id, '-.') = 0
              AND instr(NEW.authorized_near_account_id, '-_') = 0
              AND instr(NEW.authorized_near_account_id, '--') = 0
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorized NEAR account ID');
            END;

          CREATE TRIGGER authorization_intents_validate_initial_state
            BEFORE INSERT ON authorization_intents
            WHEN NEW.state != 'issued'
            BEGIN
              SELECT RAISE(ABORT, 'new authorization intents must start in issued state');
            END;

          CREATE TRIGGER authorization_intents_validate_wallet_snapshot
            BEFORE INSERT ON authorization_intents
            WHEN NOT (
              length(NEW.authorized_wallet_account_id) BETWEEN 2 AND 64
              AND NEW.authorized_wallet_account_id = lower(NEW.authorized_wallet_account_id)
              AND substr(NEW.authorized_wallet_account_id, 1, 1) GLOB '[a-z0-9]'
              AND substr(NEW.authorized_wallet_account_id, -1, 1) GLOB '[a-z0-9]'
              AND NEW.authorized_wallet_account_id NOT GLOB '*[^a-z0-9._-]*'
              AND instr(NEW.authorized_wallet_account_id, '..') = 0
              AND instr(NEW.authorized_wallet_account_id, '._') = 0
              AND instr(NEW.authorized_wallet_account_id, '.-') = 0
              AND instr(NEW.authorized_wallet_account_id, '_.') = 0
              AND instr(NEW.authorized_wallet_account_id, '__') = 0
              AND instr(NEW.authorized_wallet_account_id, '_-') = 0
              AND instr(NEW.authorized_wallet_account_id, '-.') = 0
              AND instr(NEW.authorized_wallet_account_id, '-_') = 0
              AND instr(NEW.authorized_wallet_account_id, '--') = 0
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorization wallet account ID');
            END;

          CREATE TRIGGER authorization_intents_validate_current_authorization
            BEFORE UPDATE OF state ON authorization_intents
            WHEN NEW.state = 'verifying' AND NOT EXISTS (
              SELECT 1
              FROM transactions t
              JOIN decisions d ON d.id = NEW.decision_id AND d.transaction_id = t.id
              JOIN policies p ON p.id = NEW.policy_id
                AND p.agent_id = t.agent_id
                AND CAST(p.version AS TEXT) = NEW.policy_version
              JOIN agents a ON a.id = t.agent_id
                AND a.enabled = 1
                AND a.authorized_near_account_id = NEW.authorized_wallet_account_id
              WHERE t.id = NEW.transaction_id
                AND d.policy_id = NEW.policy_id
                AND d.policy_version = NEW.policy_version
                AND p.version = (
                  SELECT MAX(current_policy.version)
                  FROM policies current_policy
                  WHERE current_policy.agent_id = p.agent_id
                )
                AND (
                  (d.decision = 'ALLOW' AND NEW.approval_id IS NULL)
                  OR (
                    d.decision = 'WARN'
                    AND EXISTS (
                      SELECT 1 FROM approvals ap
                      WHERE ap.id = NEW.approval_id
                        AND ap.decision_id = d.id
                        AND ap.status = 'approved'
                    )
                  )
                )
                AND julianday(NEW.expires_at) > julianday('now')
            )
            BEGIN
              SELECT RAISE(ABORT, 'authorization intent is stale or no longer eligible');
            END;

          DROP TRIGGER authorization_intents_validate_transition;
          CREATE TRIGGER authorization_intents_validate_transition
            BEFORE UPDATE OF state ON authorization_intents
            WHEN NOT (
              (OLD.state = 'issued' AND NEW.state IN ('verifying', 'expired', 'stale'))
              OR (OLD.state = 'indeterminate' AND NEW.state IN ('verifying', 'expired', 'stale'))
              OR (OLD.state = 'verifying' AND NEW.state IN ('verified', 'failed', 'indeterminate', 'stale'))
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorization intent state transition');
            END;

          CREATE TRIGGER authorization_intents_protect_claim
            BEFORE UPDATE OF transaction_hash, claimed_signer_account_id
            ON authorization_intents
            WHEN NOT (
              (
                OLD.state = 'issued'
                AND NEW.state = 'verifying'
                AND OLD.transaction_hash IS NULL
                AND OLD.claimed_signer_account_id IS NULL
                AND NEW.transaction_hash IS NOT NULL
                AND NEW.claimed_signer_account_id = NEW.authorized_wallet_account_id
              )
              OR (
                OLD.state = 'indeterminate'
                AND NEW.state = 'verifying'
                AND OLD.transaction_hash = NEW.transaction_hash
                AND OLD.claimed_signer_account_id = NEW.claimed_signer_account_id
              )
            )
            BEGIN
              SELECT RAISE(ABORT, 'authorization intent claim is immutable');
            END;

          CREATE TRIGGER agents_invalidate_outstanding_intents
            AFTER UPDATE OF enabled, authorized_near_account_id ON agents
            WHEN OLD.enabled != NEW.enabled
              OR OLD.authorized_near_account_id IS NOT NEW.authorized_near_account_id
            BEGIN
              INSERT INTO audit_logs (id, event_type, entity_type, entity_id, details, created_at)
              SELECT lower(hex(randomblob(16))), 'authorization_intent.stale',
                'authorization_intent', i.id,
                json_object(
                  'reason',
                  CASE
                    WHEN OLD.enabled = 1 AND NEW.enabled = 0 THEN 'agent_disabled'
                    WHEN OLD.authorized_near_account_id IS NOT NEW.authorized_near_account_id
                      THEN 'wallet_binding_changed'
                    ELSE 'agent_authorization_changed'
                  END,
                  'agentId', NEW.id
                ),
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              FROM authorization_intents i
              JOIN transactions t ON t.id = i.transaction_id
              WHERE t.agent_id = NEW.id AND i.state IN ('issued', 'indeterminate');

              UPDATE authorization_intents
              SET state = 'stale', consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE state IN ('issued', 'indeterminate')
                AND transaction_id IN (
                  SELECT id FROM transactions WHERE agent_id = NEW.id
                );
            END;

          CREATE TRIGGER policies_invalidate_outstanding_intents
            AFTER INSERT ON policies
            WHEN NEW.version = (
              SELECT MAX(version) FROM policies WHERE agent_id = NEW.agent_id
            )
            BEGIN
              INSERT INTO audit_logs (id, event_type, entity_type, entity_id, details, created_at)
              SELECT lower(hex(randomblob(16))), 'authorization_intent.stale',
                'authorization_intent', i.id,
                json_object(
                  'reason', 'policy_version_changed',
                  'previousPolicyVersion', i.policy_version,
                  'currentPolicyVersion', CAST(NEW.version AS TEXT)
                ),
                strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              FROM authorization_intents i
              JOIN transactions t ON t.id = i.transaction_id
              WHERE t.agent_id = NEW.agent_id
                AND i.state IN ('issued', 'indeterminate')
                AND i.policy_version != CAST(NEW.version AS TEXT);

              UPDATE authorization_intents
              SET state = 'stale', consumed_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
              WHERE state IN ('issued', 'indeterminate')
                AND policy_version != CAST(NEW.version AS TEXT)
                AND transaction_id IN (
                  SELECT id FROM transactions WHERE agent_id = NEW.agent_id
                );
            END;
        `);
        this.connection.pragma("user_version = 2");
      });
      migration.immediate();
    }

    if (version < 3) {
      const migration = this.connection.transaction(() => {
        this.connection.exec(`
          DROP TRIGGER IF EXISTS authorization_intents_validate_insert;
          CREATE TRIGGER authorization_intents_validate_insert
            BEFORE INSERT ON authorization_intents
            BEGIN
              SELECT CASE WHEN NOT EXISTS (
                SELECT 1
                FROM transactions t
                JOIN decisions d
                  ON d.id = NEW.decision_id
                  AND d.transaction_id = t.id
                  AND d.policy_id = NEW.policy_id
                  AND d.policy_version = NEW.policy_version
                JOIN policies p
                  ON p.id = NEW.policy_id
                  AND p.agent_id = t.agent_id
                  AND CAST(p.version AS TEXT) = NEW.policy_version
                  AND p.version = (
                    SELECT MAX(current_policy.version)
                    FROM policies current_policy
                    WHERE current_policy.agent_id = p.agent_id
                  )
                JOIN agents a
                  ON a.id = t.agent_id
                  AND a.enabled = 1
                  AND a.authorized_near_account_id = NEW.authorized_wallet_account_id
                WHERE t.id = NEW.transaction_id
                  AND t.status = d.decision
                  AND d.decision IN ('ALLOW', 'WARN')
                  AND (
                    (
                      d.decision = 'ALLOW'
                      AND NEW.approval_id IS NULL
                    )
                    OR (
                      d.decision = 'WARN'
                      AND EXISTS (
                        SELECT 1
                        FROM approvals ap
                        JOIN decisions approval_decision
                          ON approval_decision.id = ap.decision_id
                          AND approval_decision.transaction_id = t.id
                          AND approval_decision.policy_id = p.id
                          AND approval_decision.policy_version = NEW.policy_version
                        JOIN transactions approval_transaction
                          ON approval_transaction.id = approval_decision.transaction_id
                          AND approval_transaction.agent_id = t.agent_id
                        WHERE ap.id = NEW.approval_id
                          AND ap.decision_id = d.id
                          AND ap.status = 'approved'
                      )
                    )
                  )
              ) THEN RAISE(ABORT, 'authorization intent does not match eligible records') END;
            END;
        `);
        this.connection.pragma("user_version = 3");
      });
      migration.immediate();
    }

    if (version < 4) {
      const migration = this.connection.transaction(() => {
        this.connection.exec(`
          CREATE TABLE authorization_intent_revocations (
            intent_id TEXT PRIMARY KEY
              REFERENCES authorization_intents(id) ON DELETE RESTRICT,
            revoked_at TEXT NOT NULL
          );

          CREATE TRIGGER authorization_intent_revocations_validate_insert
            BEFORE INSERT ON authorization_intent_revocations
            WHEN NOT EXISTS (
              SELECT 1
              FROM authorization_intents i
              JOIN transactions t ON t.id = i.transaction_id
              JOIN decisions d
                ON d.id = i.decision_id
                AND d.transaction_id = t.id
                AND d.policy_id = i.policy_id
                AND d.policy_version = i.policy_version
                AND t.status = d.decision
                AND d.decision IN ('ALLOW', 'WARN')
              JOIN policies p
                ON p.id = i.policy_id
                AND p.agent_id = t.agent_id
                AND CAST(p.version AS TEXT) = i.policy_version
                AND p.version = (
                  SELECT MAX(current_policy.version)
                  FROM policies current_policy
                  WHERE current_policy.agent_id = p.agent_id
                )
              JOIN agents a
                ON a.id = t.agent_id
                AND a.enabled = 1
                AND a.authorized_near_account_id = i.authorized_wallet_account_id
              WHERE i.id = NEW.intent_id
                AND i.state = 'issued'
                AND i.expires_at > NEW.revoked_at
                AND (
                  (d.decision = 'ALLOW' AND i.approval_id IS NULL)
                  OR (
                    d.decision = 'WARN'
                    AND EXISTS (
                      SELECT 1
                      FROM approvals ap
                      WHERE ap.id = i.approval_id
                        AND ap.decision_id = d.id
                        AND ap.status = 'approved'
                    )
                  )
                )
            )
            BEGIN
              SELECT RAISE(ABORT, 'authorization intent is not eligible for revocation');
            END;

          CREATE TRIGGER authorization_intent_revocations_protect_update
            BEFORE UPDATE ON authorization_intent_revocations
            BEGIN
              SELECT RAISE(ABORT, 'authorization revocations are immutable');
            END;

          CREATE TRIGGER authorization_intent_revocations_protect_delete
            BEFORE DELETE ON authorization_intent_revocations
            BEGIN
              SELECT RAISE(ABORT, 'authorization revocations are immutable');
            END;

          CREATE TRIGGER authorization_intent_revocations_audit
            AFTER INSERT ON authorization_intent_revocations
            BEGIN
              INSERT INTO audit_logs (id, event_type, entity_type, entity_id, details, created_at)
              VALUES (
                lower(hex(randomblob(16))),
                'authorization_intent.revoked',
                'authorization_intent',
                NEW.intent_id,
                json_object('revokedAt', NEW.revoked_at),
                NEW.revoked_at
              );
            END;

          DROP TRIGGER IF EXISTS authorization_intents_validate_transition;
          CREATE TRIGGER authorization_intents_validate_transition
            BEFORE UPDATE OF state ON authorization_intents
            WHEN NOT (
              (
                OLD.state = 'issued'
                AND NEW.state IN ('verifying', 'expired', 'stale')
                AND NOT (
                  NEW.state = 'verifying'
                  AND EXISTS (
                    SELECT 1
                    FROM authorization_intent_revocations r
                    WHERE r.intent_id = OLD.id
                  )
                )
              )
              OR (OLD.state = 'indeterminate' AND NEW.state IN ('verifying', 'expired', 'stale'))
              OR (
                OLD.state = 'verifying'
                AND NEW.state IN ('verified', 'failed', 'indeterminate', 'stale')
              )
            )
            BEGIN
              SELECT RAISE(ABORT, 'invalid authorization intent state transition');
            END;
        `);
        this.connection.pragma("user_version = 4");
      });
      migration.immediate();
    }
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

  setAgentAuthorizedNearAccount(
    id: string,
    accountId: string | null,
    options?: { expectedCurrentAccountId: string | null },
  ): AgentRecord | undefined {
    if (accountId !== null && !isValidNearAccountId(accountId)) {
      throw new Error("Authorized NEAR account ID is invalid.");
    }

    const update = this.connection.transaction(() => {
      const current = this.getAgent(id);
      if (!current) return undefined;
      if (
        options &&
        current.authorizedNearAccountId !== options.expectedCurrentAccountId
      ) {
        throw new Error("NEAR wallet binding changed; review the current binding and retry.");
      }
      if (current.authorizedNearAccountId === accountId) return current;

      const updatedAt = now();
      this.connection
        .prepare("UPDATE agents SET authorized_near_account_id = ?, updated_at = ? WHERE id = ?")
        .run(accountId, updatedAt, id);
      this.insertAudit(
        "agent.near_account_binding_changed",
        "agent",
        id,
        { authorizedNearAccountId: accountId },
        updatedAt,
      );
      return this.getAgent(id);
    });
    return update.immediate();
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
    return update.immediate();
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
    return update.immediate();
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

  createAuthorizationIntent(
    input: NewAuthorizationIntent,
  ): AuthorizationIntentRecord {
    if (!/^[0-9a-f]{64}$/.test(input.tokenHash)) {
      throw new Error("Authorization token hash must be a SHA-256 hex digest.");
    }
    if (!isValidNearAccountId(input.authorizedWalletAccountId)) {
      throw new Error("Authorized NEAR account ID is invalid.");
    }
    const expiresAt = Date.parse(input.expiresAt);
    if (!Number.isFinite(expiresAt) || expiresAt <= Date.now()) {
      throw new Error("Authorization intent expiry must be a valid future timestamp.");
    }

    const id = randomUUID();
    const createdAt = now();
    const persist = this.connection.transaction(() => {
      if (!this.isAuthorizationIntentInputEligible(input)) {
        throw new Error("Authorization intent does not match current eligible records.");
      }
      this.connection
        .prepare(
          `INSERT INTO authorization_intents
            (id, transaction_id, decision_id, approval_id, token_hash, policy_id,
             policy_version, authorized_wallet_account_id, expires_at, created_at, state)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'issued')`,
        )
        .run(
          id,
          input.transactionId,
          input.decisionId,
          input.approvalId,
          input.tokenHash,
          input.policyId,
          input.policyVersion,
          input.authorizedWalletAccountId,
          input.expiresAt,
          createdAt,
        );
      this.insertAudit(
        "authorization_intent.issued",
        "authorization_intent",
        id,
        {
          transactionId: input.transactionId,
          decisionId: input.decisionId,
          approvalId: input.approvalId,
          policyId: input.policyId,
          policyVersion: input.policyVersion,
          authorizedWalletAccountId: input.authorizedWalletAccountId,
          expiresAt: input.expiresAt,
        },
        createdAt,
      );
    });
    persist.immediate();
    return this.getAuthorizationIntent(id)!;
  }

  private isAuthorizationIntentInputEligible(input: NewAuthorizationIntent): boolean {
    const row = this.connection
      .prepare(
        `SELECT EXISTS (
          SELECT 1
          FROM transactions t
          JOIN decisions d
            ON d.id = ?
            AND d.transaction_id = t.id
            AND d.policy_id = ?
            AND d.policy_version = ?
          JOIN policies p
            ON p.id = ?
            AND p.agent_id = t.agent_id
            AND CAST(p.version AS TEXT) = ?
            AND p.version = (
              SELECT MAX(current_policy.version)
              FROM policies current_policy
              WHERE current_policy.agent_id = p.agent_id
            )
          JOIN agents a
            ON a.id = t.agent_id
            AND a.enabled = 1
            AND a.authorized_near_account_id = ?
          WHERE t.id = ?
            AND t.status = d.decision
            AND d.decision IN ('ALLOW', 'WARN')
            AND (
              (d.decision = 'ALLOW' AND ? IS NULL)
              OR (
                d.decision = 'WARN'
                AND EXISTS (
                  SELECT 1
                  FROM approvals ap
                  JOIN decisions approval_decision
                    ON approval_decision.id = ap.decision_id
                    AND approval_decision.transaction_id = t.id
                    AND approval_decision.policy_id = p.id
                    AND approval_decision.policy_version = ?
                  JOIN transactions approval_transaction
                    ON approval_transaction.id = approval_decision.transaction_id
                    AND approval_transaction.agent_id = t.agent_id
                  WHERE ap.id = ?
                    AND ap.decision_id = d.id
                    AND ap.status = 'approved'
                )
              )
            )
        ) AS eligible`,
      )
      .get(
        input.decisionId,
        input.policyId,
        input.policyVersion,
        input.policyId,
        input.policyVersion,
        input.authorizedWalletAccountId,
        input.transactionId,
        input.approvalId,
        input.policyVersion,
        input.approvalId,
      ) as { eligible: number };
    return row.eligible === 1;
  }

  getAuthorizationIntent(id: string): AuthorizationIntentRecord | undefined {
    const row = this.connection
      .prepare("SELECT * FROM authorization_intents WHERE id = ?")
      .get(id) as Record<string, unknown> | undefined;
    const intent = decodeAuthorizationIntent(row);
    if (!intent) return undefined;
    const revocation = this.connection
      .prepare("SELECT 1 FROM authorization_intent_revocations WHERE intent_id = ?")
      .get(id);
    return revocation ? { ...intent, state: "revoked" } : intent;
  }

  getAuthorizationIntentByTokenHash(
    transactionId: string,
    tokenHash: string,
  ): AuthorizationIntentRecord | undefined {
    const row = this.connection
      .prepare(
        "SELECT * FROM authorization_intents WHERE transaction_id = ? AND token_hash = ?",
      )
      .get(transactionId, tokenHash) as Record<string, unknown> | undefined;
    return decodeAuthorizationIntent(row);
  }

  private isAuthorizationIntentCurrentlyEligible(
    intent: AuthorizationIntentRecord,
    requireUnexpired: boolean,
  ): boolean {
    if (requireUnexpired && Date.parse(intent.expiresAt) <= Date.now()) return false;
    const row = this.connection
      .prepare(
        `SELECT EXISTS (
          SELECT 1
          FROM transactions t
          JOIN decisions d ON d.id = ? AND d.transaction_id = t.id
          JOIN policies p ON p.id = ?
            AND p.agent_id = t.agent_id
            AND CAST(p.version AS TEXT) = ?
          JOIN agents a ON a.id = t.agent_id
            AND a.enabled = 1
            AND a.authorized_near_account_id = ?
          WHERE t.id = ?
            AND d.policy_id = p.id
            AND d.policy_version = ?
            AND d.decision IN ('ALLOW', 'WARN')
            AND p.version = (
              SELECT MAX(current_policy.version)
              FROM policies current_policy
              WHERE current_policy.agent_id = p.agent_id
            )
            AND (
              (d.decision = 'ALLOW' AND ? IS NULL)
              OR (
                d.decision = 'WARN'
                AND EXISTS (
                  SELECT 1 FROM approvals ap
                  WHERE ap.id = ?
                    AND ap.decision_id = d.id
                    AND ap.status = 'approved'
                )
              )
            )
        ) AS eligible`,
      )
      .get(
        intent.decisionId,
        intent.policyId,
        intent.policyVersion,
        intent.authorizedWalletAccountId,
        intent.transactionId,
        intent.policyVersion,
        intent.approvalId,
        intent.approvalId,
      ) as { eligible: number };
    return row.eligible === 1;
  }

  private setAuthorizationIntentState(
    id: string,
    state: "expired" | "stale",
    reason: string,
    timestamp: string,
  ): AuthorizationIntentRecord | undefined {
    const update = this.connection
      .prepare(
        `UPDATE authorization_intents
         SET state = ?, consumed_at = ?
         WHERE id = ? AND state IN ('issued', 'indeterminate')`,
      )
      .run(state, timestamp, id);
    if (update.changes !== 1) return this.getAuthorizationIntent(id);
    this.insertAudit(
      `authorization_intent.${state}`,
      "authorization_intent",
      id,
      { reason },
      timestamp,
    );
    return this.getAuthorizationIntent(id);
  }

  revokeAuthorizationIntent(
    id: string,
    tokenHash: string,
  ): {
    status: "revoked" | "expired" | "stale" | "not-revocable";
    intent?: AuthorizationIntentRecord;
    revokedAt?: string;
  } {
    const revoke = this.connection.transaction(() => {
      const intent = this.getAuthorizationIntent(id);
      if (!intent || intent.state !== "issued") {
        return { status: "not-revocable" as const };
      }
      if (!/^[0-9a-f]{64}$/.test(tokenHash) || tokenHash !== intent.tokenHash) {
        return { status: "not-revocable" as const };
      }
      if (Date.parse(intent.expiresAt) <= Date.now()) {
        const expired = this.setAuthorizationIntentState(
          id,
          "expired",
          "Intent expired before revocation.",
          now(),
        );
        return { status: "expired" as const, ...(expired ? { intent: expired } : {}) };
      }
      if (!this.isAuthorizationIntentCurrentlyEligible(intent, true)) {
        const stale = this.setAuthorizationIntentState(
          id,
          "stale",
          "Agent, wallet binding, policy, or approval changed before revocation.",
          now(),
        );
        return { status: "stale" as const, ...(stale ? { intent: stale } : {}) };
      }

      const revokedAt = now();
      const inserted = this.connection
        .prepare(
          `INSERT INTO authorization_intent_revocations (intent_id, revoked_at)
           SELECT ?, ?
           WHERE EXISTS (
             SELECT 1
             FROM authorization_intents i
             WHERE i.id = ?
               AND i.state = 'issued'
               AND i.token_hash = ?
               AND i.expires_at > ?
           )`,
        )
        .run(id, revokedAt, id, tokenHash, revokedAt);
      if (inserted.changes !== 1) return { status: "not-revocable" as const };
      const revokedIntent = this.getAuthorizationIntent(id);
      return revokedIntent
        ? { status: "revoked" as const, intent: revokedIntent, revokedAt }
        : { status: "not-revocable" as const };
    });
    return revoke.immediate();
  }

  startAuthorizationIntentVerification(
    id: string,
    transactionHash: string,
    claimedSignerAccountId: string,
  ): AuthorizationIntentRecord | undefined {
    if (
      !isValidNearTransactionHash(transactionHash) ||
      !isValidNearAccountId(claimedSignerAccountId)
    ) {
      return undefined;
    }
    const start = this.connection.transaction(() => {
      const intent = this.getAuthorizationIntent(id);
      if (!intent || intent.authorizedWalletAccountId !== claimedSignerAccountId) {
        return undefined;
      }
      if (intent.state === "revoked") return undefined;
      if (Date.parse(intent.expiresAt) <= Date.now()) {
        this.setAuthorizationIntentState(id, "expired", "Intent expired before verification.", now());
        return undefined;
      }
      if (!this.isAuthorizationIntentCurrentlyEligible(intent, true)) {
        this.setAuthorizationIntentState(
          id,
          "stale",
          "Agent, wallet binding, policy, or approval changed before verification.",
          now(),
        );
        return undefined;
      }
      const isRetry =
        intent.state === "indeterminate" &&
        intent.transactionHash === transactionHash &&
        intent.claimedSignerAccountId === claimedSignerAccountId;
      if (
        (intent.state !== "issued" && !isRetry)
      ) {
        return undefined;
      }
      const priorVerification = this.connection
        .prepare("SELECT authorization_intent_id FROM chain_verifications WHERE transaction_hash = ?")
        .get(transactionHash) as { authorization_intent_id: string } | undefined;
      if (priorVerification && priorVerification.authorization_intent_id !== intent.id) {
        return undefined;
      }
      const priorClaim = this.connection
        .prepare(
          "SELECT id FROM authorization_intents WHERE transaction_hash = ? AND id != ? LIMIT 1",
        )
        .get(transactionHash, intent.id) as { id: string } | undefined;
      if (priorClaim) return undefined;
      const updated = this.connection
        .prepare(
          `UPDATE authorization_intents
           SET state = 'verifying', transaction_hash = ?, claimed_signer_account_id = ?
           WHERE id = ? AND state = ?`,
        )
        .run(transactionHash, claimedSignerAccountId, id, intent.state);
      if (updated.changes !== 1) return undefined;
      const createdAt = now();
      this.insertAudit(
        "authorization_intent.verification_started",
        "authorization_intent",
        id,
        { transactionHash, claimedSignerAccountId },
        createdAt,
      );
      return this.getAuthorizationIntent(id);
    });
    return start.immediate();
  }

  invalidateAuthorizationIntent(
    id: string,
    state: "expired" | "stale",
    reason: string,
  ): AuthorizationIntentRecord | undefined {
    const invalidate = this.connection.transaction(() => {
      const updatedAt = now();
      return this.setAuthorizationIntentState(id, state, reason, updatedAt);
    });
    return invalidate.immediate();
  }

  completeAuthorizationIntentVerification(
    verification: NewChainVerification,
  ): CompletedChainVerification {
    let intentState: AuthorizationIntentState =
      verification.status === "verified"
        ? "verified"
        : verification.status === "failed"
          ? "failed"
          : "indeterminate";
    const createdAt = now();
    const consumedAt = intentState === "indeterminate" ? null : verification.verifiedAt;

    const complete = this.connection.transaction(() => {
      const intent = this.getAuthorizationIntent(verification.authorizationIntentId);
      if (
        !intent ||
        intent.state !== "verifying" ||
        intent.transactionHash !== verification.transactionHash
      ) {
        throw new Error("Authorization intent is not verifying this transaction hash.");
      }
      const expiredDuringVerification = Date.parse(intent.expiresAt) <= Date.now();
      if (
        expiredDuringVerification ||
        !this.isAuthorizationIntentCurrentlyEligible(intent, false)
      ) {
        intentState = "stale";
      }
      const existing = this.connection
        .prepare("SELECT * FROM chain_verifications WHERE transaction_hash = ?")
        .get(verification.transactionHash) as Record<string, unknown> | undefined;
      let verificationId: string;
      if (existing) {
        if (String(existing.authorization_intent_id) !== intent.id) {
          throw new Error(
            "Transaction hash is already associated with another authorization intent.",
          );
        }
        verificationId = String(existing.id);
        this.connection
          .prepare(
            `UPDATE chain_verifications
             SET status = ?, reason = ?, observed_signer_account_id = ?,
                 observed_receiver_account_id = ?, observed_amount_yocto = ?,
                 verified_at = ?
             WHERE id = ?`,
          )
          .run(
            verification.status,
            verification.reason,
            verification.observedSignerAccountId,
            verification.observedReceiverAccountId,
            verification.observedAmountYocto,
            verification.verifiedAt,
            verificationId,
          );
      } else {
        verificationId = randomUUID();
        this.connection
          .prepare(
            `INSERT INTO chain_verifications
              (id, authorization_intent_id, transaction_hash, status, reason,
               observed_signer_account_id, observed_receiver_account_id,
               observed_amount_yocto, created_at, verified_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          )
          .run(
            verificationId,
            intent.id,
            verification.transactionHash,
            verification.status,
            verification.reason,
            verification.observedSignerAccountId,
            verification.observedReceiverAccountId,
            verification.observedAmountYocto,
            createdAt,
            verification.verifiedAt,
          );
      }
      this.connection
        .prepare("UPDATE authorization_intents SET state = ?, consumed_at = ? WHERE id = ?")
        .run(
          intentState,
          intentState === "stale" ? verification.verifiedAt : consumedAt,
          intent.id,
        );
      if (intentState === "stale") {
        this.insertAudit(
          "authorization_intent.stale",
          "authorization_intent",
          intent.id,
          {
            reason: expiredDuringVerification
              ? "Authorization intent expired during chain verification."
              : "Authorization changed during chain verification.",
          },
          verification.verifiedAt,
        );
      }
      this.insertAudit(
        "chain_verification.completed",
        "authorization_intent",
        intent.id,
        {
          transactionHash: verification.transactionHash,
          status: verification.status,
          reason: verification.reason,
          intentState,
          observedSignerAccountId: verification.observedSignerAccountId,
          observedReceiverAccountId: verification.observedReceiverAccountId,
          observedAmountYocto: verification.observedAmountYocto,
        },
        verification.verifiedAt,
      );
      const row = this.connection
        .prepare("SELECT * FROM chain_verifications WHERE id = ?")
        .get(verificationId) as Record<string, unknown>;
      return {
        ...decodeChainVerification(row)!,
        authorizationIntentState: intentState,
      };
    });
    return complete.immediate();
  }

  getChainVerification(intentId: string): ChainVerificationRecord | undefined {
    const row = this.connection
      .prepare(
        "SELECT * FROM chain_verifications WHERE authorization_intent_id = ? ORDER BY created_at DESC LIMIT 1",
      )
      .get(intentId) as Record<string, unknown> | undefined;
    return decodeChainVerification(row);
  }

  getChainVerificationByTransactionHash(
    transactionHash: string,
  ): ChainVerificationRecord | undefined {
    const row = this.connection
      .prepare("SELECT * FROM chain_verifications WHERE transaction_hash = ?")
      .get(transactionHash) as Record<string, unknown> | undefined;
    return decodeChainVerification(row);
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

  createThreatSimulation(
    simulation: NewThreatSimulation,
  ): ThreatSimulationRecord {
    const id = randomUUID();
    const createdAt = now();
    const persist = this.connection.transaction(() => {
      this.connection
        .prepare(
          `INSERT INTO threat_simulations
            (id, agent_id, policy_id, scenario_id, description, malicious_instruction,
             simulated_response, proposed_transaction, checks_performed, decision, explanation,
             triggered_policy_rules, outcome, is_simulation, executed, policy_version, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)`,
        )
        .run(
          id,
          simulation.agentId,
          simulation.policyId,
          simulation.scenarioId,
          simulation.description,
          simulation.maliciousInstruction,
          simulation.simulatedResponse,
          JSON.stringify(simulation.proposedTransaction),
          JSON.stringify(simulation.checksPerformed),
          simulation.decision,
          simulation.explanation,
          JSON.stringify(simulation.triggeredPolicyRules),
          simulation.outcome,
          simulation.policyVersion,
          createdAt,
        );
      this.insertAudit(
        "threat_lab.simulation.completed",
        "threat_simulation",
        id,
        {
          agentId: simulation.agentId,
          scenarioId: simulation.scenarioId,
          decision: simulation.decision,
          outcome: simulation.outcome,
          policyVersion: simulation.policyVersion,
          isSimulation: true,
          executed: false,
        },
        createdAt,
      );
    });
    persist();
    return this.getThreatSimulation(id)!;
  }

  getThreatSimulation(id: string): ThreatSimulationRecord | undefined {
    const row = this.connection
      .prepare("SELECT * FROM threat_simulations WHERE id = ?")
      .get(id) as Record<string, unknown> | undefined;
    if (!row) return undefined;
    return {
      id: String(row.id),
      agentId: String(row.agent_id),
      policyId: String(row.policy_id),
      scenarioId: String(row.scenario_id),
      description: String(row.description),
      maliciousInstruction: String(row.malicious_instruction),
      simulatedResponse: String(row.simulated_response),
      proposedTransaction: JSON.parse(String(row.proposed_transaction)) as Transaction,
      checksPerformed: JSON.parse(String(row.checks_performed)) as string[],
      decision: row.decision as PolicyDecision["decision"],
      explanation: String(row.explanation),
      triggeredPolicyRules: JSON.parse(String(row.triggered_policy_rules)) as string[],
      outcome: row.outcome as ThreatSimulationRecord["outcome"],
      isSimulation: true,
      executed: false,
      policyVersion: String(row.policy_version),
      createdAt: String(row.created_at),
    };
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
