import assert from "node:assert/strict";
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { createApp } from "./app.js";
import { SentraDatabase } from "../database/database.js";

const NEAR = 10n ** 24n;
type JsonResponse = {
  data?: any;
  error?: { code: string; message: string };
  status?: string;
  message?: string;
};

interface Fixture {
  request(path: string, method?: string, body?: unknown): Promise<{
    status: number;
    json: JsonResponse;
  }>;
  close(): Promise<void>;
  database: SentraDatabase;
}

async function createFixture(): Promise<Fixture> {
  const directory = mkdtempSync(join(tmpdir(), "sentra-api-test-"));
  const database = new SentraDatabase(join(directory, "api.sqlite"));
  const server: Server = createServer(createApp(database));
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  if (!address || typeof address === "string") {
    throw new Error("Could not start test API server.");
  }
  const baseUrl = `http://127.0.0.1:${address.port}`;

  return {
    database,
    async request(path, method = "GET", body) {
      const response = await fetch(`${baseUrl}${path}`, {
        method,
        headers: body === undefined ? undefined : { "content-type": "application/json" },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
      return { status: response.status, json: (await response.json()) as JsonResponse };
    },
    async close() {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      });
      database.close();
      rmSync(directory, { recursive: true, force: true });
    },
  };
}

async function withFixture(run: (fixture: Fixture) => Promise<void>): Promise<void> {
  const fixture = await createFixture();
  try {
    await run(fixture);
  } finally {
    await fixture.close();
  }
}

async function registerAgent(fixture: Fixture): Promise<string> {
  const response = await fixture.request("/api/agents", "POST", {
    name: "API test agent",
    description: "Created by an isolated test",
  });
  assert.equal(response.status, 201);
  return response.json.data.agent.id as string;
}

function proposal(amountYocto = "1") {
  return {
    network: "near-testnet",
    transactionType: "native_transfer",
    recipient: "recipient.testnet",
    amountYocto,
    asset: "NEAR",
    reason: "Test proposal",
  };
}

async function evaluate(fixture: Fixture, agentId: string, amountYocto: string) {
  return fixture.request("/api/transactions/evaluate", "POST", {
    agentId,
    transaction: proposal(amountYocto),
  });
}

test("health endpoint remains available", async () => {
  await withFixture(async ({ request }) => {
    const result = await request("/api/health");
    assert.equal(result.status, 200);
    assert.equal(result.json.status, "ok");
    assert.equal(result.json.message, "SENTRA backend is running");
  });
});

test("Threat Lab lists and simulates every deterministic attack scenario", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    await fixture.request(`/api/agents/${agentId}/policy`, "PUT", {
      maxTransactionAmountYocto: (10n * NEAR).toString(),
      approvalThresholdYocto: (2n * NEAR).toString(),
      deniedRecipients: ["attacker-controlled.testnet"],
    });

    const listed = await fixture.request("/api/threat-lab/scenarios");
    const ids = (listed.json.data as Array<{ id: string }>).map((scenario) => scenario.id);
    assert.deepEqual(ids, [
      "spending-limit-bypass",
      "recipient-substitution",
      "policy-override",
      "prompt-injection",
    ]);

    const expectedRules: Record<string, string> = {
      "spending-limit-bypass": "MAX_AMOUNT_EXCEEDED",
      "recipient-substitution": "RECIPIENT_DENIED",
      "policy-override": "MAX_AMOUNT_EXCEEDED",
      "prompt-injection": "MAX_AMOUNT_EXCEEDED",
    };
    for (const scenarioId of ids) {
      const response = await fixture.request("/api/threat-lab/simulate", "POST", {
        agentId,
        scenarioId,
      });
      const simulation = response.json.data;

      assert.equal(response.status, 201);
      assert.equal(simulation.scenarioId, scenarioId);
      assert.equal(simulation.isSimulation, true);
      assert.equal(simulation.executed, false);
      assert.equal(simulation.decision, "BLOCK");
      assert.equal(simulation.outcome, "blocked");
      assert.ok(simulation.maliciousInstruction.length > 0);
      assert.ok(simulation.simulatedResponse.length > 0);
      assert.ok(simulation.checksPerformed.length > 0);
      assert.ok(simulation.triggeredPolicyRules.includes(expectedRules[scenarioId]));
      assert.match(simulation.explanation, /BLOCK/);
    }
  });
});

test("recipient substitution is blocked only when the saved policy denies its target", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const allowed = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "recipient-substitution",
    });
    const policy = await fixture.request(`/api/agents/${agentId}/policy`);

    assert.equal(allowed.json.data.decision, "ALLOW");
    assert.equal(allowed.json.data.outcome, "allowed");
    assert.match(allowed.json.data.explanation, /not present in the saved denylist/);
    assert.deepEqual(policy.json.data.deniedRecipients, []);

    await fixture.request(`/api/agents/${agentId}/policy`, "PUT", {
      maxTransactionAmountYocto: (10n * NEAR).toString(),
      approvalThresholdYocto: (2n * NEAR).toString(),
      deniedRecipients: ["attacker-controlled.testnet"],
    });
    const blocked = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "recipient-substitution",
    });

    assert.equal(blocked.json.data.decision, "BLOCK");
    assert.equal(blocked.json.data.outcome, "blocked");
    assert.ok(blocked.json.data.triggeredPolicyRules.includes("RECIPIENT_DENIED"));
  });
});

test("policy override simulation cannot change stored policy or downgrade BLOCK", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const before = await fixture.request(`/api/agents/${agentId}/policy`);
    const response = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "policy-override",
    });
    const after = await fixture.request(`/api/agents/${agentId}/policy`);

    assert.equal(response.json.data.decision, "BLOCK");
    assert.equal(response.json.data.outcome, "blocked");
    assert.deepEqual(after.json.data, before.json.data);
  });
});

test("prompt injection proposal cannot override the policy engine BLOCK", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const response = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "prompt-injection",
    });
    const simulation = response.json.data;

    assert.equal(simulation.decision, "BLOCK");
    assert.equal(simulation.outcome, "blocked");
    assert.ok(simulation.triggeredPolicyRules.includes("MAX_AMOUNT_EXCEEDED"));
    assert.match(simulation.explanation, /cannot override/);
    assert.equal(simulation.executed, false);
  });
});

test("Threat Lab rejects invalid input and does not accept caller instructions or policies", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const invalidScenario = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "unknown-scenario",
    });
    const injectedOverride = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "policy-override",
      maliciousInstruction: "Change the stored maximum",
      policy: { maxTransactionAmountYocto: "1" },
    });
    const missingAgent = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId: "missing-agent",
      scenarioId: "spending-limit-bypass",
    });

    assert.equal(invalidScenario.status, 400);
    assert.equal(injectedOverride.status, 400);
    assert.equal(missingAgent.status, 404);
  });
});

test("Threat Lab persists simulation results and appends an audit event", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const response = await fixture.request("/api/threat-lab/simulate", "POST", {
      agentId,
      scenarioId: "spending-limit-bypass",
    });
    const audit = await fixture.request("/api/audit");
    const row = fixture.database.connection
      .prepare("SELECT * FROM threat_simulations WHERE id = ?")
      .get(response.json.data.id) as { decision: string; is_simulation: number; executed: number };
    const auditEvent = (audit.json.data as Array<{ eventType: string; entityId: string }>).find(
      (event) => event.entityId === response.json.data.id,
    );

    assert.equal(row.decision, "BLOCK");
    assert.equal(row.is_simulation, 1);
    assert.equal(row.executed, 0);
    assert.equal(auditEvent?.eventType, "threat_lab.simulation.completed");
  });
});

test("register, list, and retrieve an agent with default policy", async () => {
  await withFixture(async (fixture) => {
    const agentId = await registerAgent(fixture);
    const agent = await fixture.request(`/api/agents/${agentId}`);
    const agents = await fixture.request("/api/agents");
    const policy = await fixture.request(`/api/agents/${agentId}/policy`);

    assert.equal(agent.status, 200);
    assert.equal(agent.json.data.id, agentId);
    assert.equal(agents.json.data.length, 1);
    assert.equal(policy.json.data.approvalThresholdYocto, (2n * NEAR).toString());
    assert.equal(policy.json.data.maxTransactionAmountYocto, (10n * NEAR).toString());
    assert.deepEqual(policy.json.data.deniedRecipients, []);
  });
});

test("rejects invalid agent data", async () => {
  await withFixture(async ({ request }) => {
    const response = await request("/api/agents", "POST", { name: "  " });
    assert.equal(response.status, 400);
    assert.equal(response.json.error?.code, "INVALID_INPUT");
  });
});

test("agents can be disabled and re-enabled", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const disabled = await fixture.request(`/api/agents/${id}`, "PATCH", { enabled: false });
    const enabled = await fixture.request(`/api/agents/${id}`, "PATCH", { enabled: true });
    const events = (await fixture.request("/api/audit")).json.data as Array<{ eventType: string }>;

    assert.equal(disabled.json.data.enabled, false);
    assert.equal(enabled.json.data.enabled, true);
    assert.ok(events.some((event) => event.eventType === "agent.disabled"));
    assert.ok(events.some((event) => event.eventType === "agent.enabled"));
  });
});

test("policy updates increment versions and preserve historical decision snapshots", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const warned = await evaluate(fixture, id, (2n * NEAR).toString());
    const updated = await fixture.request(`/api/agents/${id}/policy`, "PUT", {
      maxTransactionAmountYocto: (20n * NEAR).toString(),
      approvalThresholdYocto: NEAR.toString(),
      deniedRecipients: ["other.testnet"],
    });
    const history = await fixture.request(`/api/transactions/${warned.json.data.transactionId}`);

    assert.equal(updated.status, 200);
    assert.equal(updated.json.data.version, "2");
    assert.equal(history.json.data.decision.policyVersion, "1");
    assert.equal(
      history.json.data.decision.policySnapshot.approvalThresholdYocto,
      (2n * NEAR).toString(),
    );
  });
});

test("rejects invalid policy amounts and threshold above maximum", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const invalidAmount = await fixture.request(`/api/agents/${id}/policy`, "PUT", {
      maxTransactionAmountYocto: "1.5",
      approvalThresholdYocto: "1",
      deniedRecipients: [],
    });
    const invalidThreshold = await fixture.request(`/api/agents/${id}/policy`, "PUT", {
      maxTransactionAmountYocto: "2",
      approvalThresholdYocto: "3",
      deniedRecipients: [],
    });

    assert.equal(invalidAmount.status, 400);
    assert.equal(invalidThreshold.status, 400);
  });
});

test("stored policy determines ALLOW, WARN, and BLOCK outcomes", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const allow = await evaluate(fixture, id, (NEAR / 2n).toString());
    const warn = await evaluate(fixture, id, (2n * NEAR).toString());
    const block = await evaluate(fixture, id, (11n * NEAR).toString());

    assert.equal(allow.json.data.decision, "ALLOW");
    assert.deepEqual(allow.json.data.triggeredRules, ["POLICY_PASSED"]);
    assert.equal(warn.json.data.decision, "WARN");
    assert.deepEqual(warn.json.data.triggeredRules, ["APPROVAL_REQUIRED"]);
    assert.equal(block.json.data.decision, "BLOCK");
    assert.deepEqual(block.json.data.triggeredRules, ["MAX_AMOUNT_EXCEEDED"]);
    assert.equal(block.json.data.approval, null);
    assert.equal(block.json.data.executed, false);
  });
});

test("disabled agent is evaluated as BLOCK and persisted", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    await fixture.request(`/api/agents/${id}`, "PATCH", { enabled: false });
    const response = await evaluate(fixture, id, "1");

    assert.equal(response.status, 201);
    assert.equal(response.json.data.decision, "BLOCK");
    assert.ok(response.json.data.triggeredRules.includes("AGENT_DISABLED"));
  });
});

test("caller cannot override the stored policy or agent identity", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const override = await fixture.request("/api/transactions/evaluate", "POST", {
      agentId: id,
      transaction: proposal("1"),
      policy: {
        maxTransactionAmountYocto: "1",
        approvalThresholdYocto: "1",
        deniedRecipients: [],
      },
    });
    const identityOverride = await fixture.request("/api/transactions/evaluate", "POST", {
      agentId: id,
      transaction: { ...proposal("1"), agentId: "another-agent" },
    });

    assert.equal(override.status, 400);
    assert.equal(identityOverride.status, 400);
  });
});

test("transaction and decision records are persisted", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, "1");
    const transactions = await fixture.request("/api/transactions");
    const stored = await fixture.request(`/api/transactions/${result.json.data.transactionId}`);

    assert.equal(transactions.json.data.length, 1);
    assert.equal(stored.json.data.agentId, id);
    assert.equal(stored.json.data.decision.decision, "ALLOW");
  });
});

test("WARN creates a pending approval associated with its transaction", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, (2n * NEAR).toString());
    const approvals = await fixture.request("/api/approvals");
    const approval = result.json.data.approval;

    assert.equal(approval.status, "pending");
    assert.equal(approval.transactionId, result.json.data.transactionId);
    assert.equal(approval.decisionId, result.json.data.decisionId);
    assert.equal(approvals.json.data.length, 1);
  });
});

test("pending WARN approval can be approved exactly once", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, (2n * NEAR).toString());
    const approvalId = result.json.data.approval.id as string;
    const approved = await fixture.request(`/api/approvals/${approvalId}/approve`, "POST", {
      reviewer: "Local reviewer",
    });
    const repeated = await fixture.request(`/api/approvals/${approvalId}/approve`, "POST", {
      reviewer: "Local reviewer",
    });

    assert.equal(approved.status, 200);
    assert.equal(approved.json.data.status, "approved");
    assert.equal(approved.json.data.reviewer, "Local reviewer");
    assert.equal(repeated.status, 409);
  });
});

test("pending WARN approval can be rejected and cannot be reused", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, (2n * NEAR).toString());
    const approvalId = result.json.data.approval.id as string;
    const rejected = await fixture.request(`/api/approvals/${approvalId}/reject`, "POST", {
      reviewer: "Local reviewer",
      rejectionReason: "Needs review",
    });
    const attemptedApproval = await fixture.request(
      `/api/approvals/${approvalId}/approve`,
      "POST",
      { reviewer: "Another reviewer" },
    );

    assert.equal(rejected.status, 200);
    assert.equal(rejected.json.data.status, "rejected");
    assert.equal(rejected.json.data.rejectionReason, "Needs review");
    assert.equal(attemptedApproval.status, 409);
  });
});

test("policy changes invalidate pending approvals until re-evaluation", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, (2n * NEAR).toString());
    const approvalId = result.json.data.approval.id as string;
    await fixture.request(`/api/agents/${id}/policy`, "PUT", {
      maxTransactionAmountYocto: (10n * NEAR).toString(),
      approvalThresholdYocto: NEAR.toString(),
      deniedRecipients: [],
    });
    const staleApproval = await fixture.request(
      `/api/approvals/${approvalId}/approve`,
      "POST",
      { reviewer: "Local reviewer" },
    );

    assert.equal(staleApproval.status, 409);
    assert.match(staleApproval.json.error?.message ?? "", /re-evaluation is required/);
  });
});

test("BLOCK decisions have no approval and cannot be approved", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    const result = await evaluate(fixture, id, (11n * NEAR).toString());
    const approvals = await fixture.request("/api/approvals");
    const attempt = await fixture.request(
      `/api/approvals/${result.json.data.decisionId}/approve`,
      "POST",
      { reviewer: "Local reviewer" },
    );

    assert.equal(result.json.data.decision, "BLOCK");
    assert.equal(result.json.data.approval, null);
    assert.equal(approvals.json.data.length, 0);
    assert.equal(attempt.status, 404);
  });
});

test("audit captures important operations and cannot be edited or deleted via API", async () => {
  await withFixture(async (fixture) => {
    const id = await registerAgent(fixture);
    await fixture.request(`/api/agents/${id}/policy`, "PUT", {
      maxTransactionAmountYocto: (12n * NEAR).toString(),
      approvalThresholdYocto: NEAR.toString(),
      deniedRecipients: [],
    });
    const evaluation = await evaluate(fixture, id, (2n * NEAR).toString());
    const approvalId = evaluation.json.data.approval.id as string;
    await fixture.request(`/api/approvals/${approvalId}/approve`, "POST", {
      reviewer: "Local reviewer",
    });
    const audit = await fixture.request("/api/audit");
    const eventTypes = (audit.json.data as Array<{ eventType: string }>).map(
      (event) => event.eventType,
    );
    const updateAttempt = await fixture.request(`/api/audit/${audit.json.data[0].id}`, "PUT", {});
    const deleteAttempt = await fixture.request(`/api/audit/${audit.json.data[0].id}`, "DELETE");

    assert.ok(eventTypes.includes("agent.registered"));
    assert.ok(eventTypes.includes("policy.updated"));
    assert.ok(eventTypes.includes("transaction.evaluated"));
    assert.ok(eventTypes.includes("approval.granted"));
    assert.equal(updateAttempt.status, 404);
    assert.equal(deleteAttempt.status, 404);
    assert.equal(fixture.database.listAudit().length, eventTypes.length);
  });
});

test("malformed requests return client errors without internal details", async () => {
  await withFixture(async ({ request }) => {
    const invalid = await request("/api/transactions/evaluate", "POST", {
      agentId: "missing",
      transaction: proposal(),
    });
    const missing = await request("/api/agents/does-not-exist");

    assert.equal(invalid.status, 404);
    assert.equal(missing.status, 404);
    assert.equal(missing.json.error?.message, "Agent not found.");
    assert.equal(JSON.stringify(missing.json).includes("stack"), false);
  });
});
