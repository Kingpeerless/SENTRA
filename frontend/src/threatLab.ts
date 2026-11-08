import type { TransactionDecision } from "./transactionAuthorization.ts";
import { authenticatedApiFetch } from "./apiAccess.ts";

export const THREAT_SCENARIO_IDS = [
  "spending-limit-bypass",
  "recipient-substitution",
  "policy-override",
  "prompt-injection",
] as const;

export interface ThreatScenario {
  id: (typeof THREAT_SCENARIO_IDS)[number];
  name: string;
  description: string;
  maliciousInstruction: string;
}

export interface ThreatSimulation {
  id: string;
  agentId: string;
  scenarioId: ThreatScenario["id"];
  description: string;
  maliciousInstruction: string;
  simulatedResponse: string;
  proposedTransaction: {
    network: string;
    transactionType: string;
    recipient: string;
    amountYocto: string;
    asset: string;
  };
  checksPerformed: string[];
  decision: TransactionDecision;
  explanation: string;
  triggeredPolicyRules: string[];
  outcome: "blocked" | "warned" | "allowed";
  isSimulation: true;
  executed: false;
  policyVersion: string;
  createdAt: string;
}

export interface ThreatAuditEvent {
  id: string;
  eventType: string;
  entityId: string;
  createdAt: string;
  details: Record<string, unknown>;
}

export interface ThreatSimulationResult {
  simulation: ThreatSimulation;
  auditEvent: ThreatAuditEvent | null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function isScenarioId(value: unknown): value is ThreatScenario["id"] {
  return typeof value === "string" &&
    (THREAT_SCENARIO_IDS as readonly string[]).includes(value);
}

function apiError(payload: unknown, fallback: string): string {
  return isRecord(payload) &&
      isRecord(payload.error) &&
      typeof payload.error.message === "string"
    ? payload.error.message
    : fallback;
}

export function parseThreatScenariosResponse(payload: unknown): ThreatScenario[] {
  if (!isRecord(payload) || !Array.isArray(payload.data)) {
    throw new Error("SENTRA returned an invalid Threat Lab scenarios response.");
  }
  const scenarios = payload.data.map((scenario): ThreatScenario => {
    if (
      !isRecord(scenario) ||
      !isScenarioId(scenario.id) ||
      typeof scenario.name !== "string" ||
      typeof scenario.description !== "string" ||
      typeof scenario.maliciousInstruction !== "string"
    ) {
      throw new Error("SENTRA returned malformed Threat Lab scenario data.");
    }
    return {
      id: scenario.id,
      name: scenario.name,
      description: scenario.description,
      maliciousInstruction: scenario.maliciousInstruction,
    };
  });
  if (
    scenarios.length !== THREAT_SCENARIO_IDS.length ||
    THREAT_SCENARIO_IDS.some((id) => !scenarios.some((scenario) => scenario.id === id))
  ) {
    throw new Error("SENTRA did not return all four supported Threat Lab scenarios.");
  }
  return scenarios;
}

export async function loadThreatScenarios(
  fetchImplementation: typeof fetch = fetch,
): Promise<ThreatScenario[]> {
  const response = await authenticatedApiFetch("/api/threat-lab/scenarios", {
    method: "GET",
    headers: { accept: "application/json" },
    cache: "no-store",
  }, fetchImplementation);
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid Threat Lab scenarios response.");
  }
  if (!response.ok) {
    throw new Error(apiError(payload, "SENTRA could not load Threat Lab scenarios."));
  }
  return parseThreatScenariosResponse(payload);
}

function parseSimulation(payload: unknown, expectedAgentId: string): ThreatSimulation {
  if (!isRecord(payload) || !isRecord(payload.data)) {
    throw new Error("SENTRA returned an invalid Threat Lab simulation response.");
  }
  const data = payload.data;
  const proposal = data.proposedTransaction;
  if (
    typeof data.id !== "string" ||
    data.agentId !== expectedAgentId ||
    !isScenarioId(data.scenarioId) ||
    typeof data.description !== "string" ||
    typeof data.maliciousInstruction !== "string" ||
    typeof data.simulatedResponse !== "string" ||
    !isRecord(proposal) ||
    typeof proposal.network !== "string" ||
    typeof proposal.transactionType !== "string" ||
    typeof proposal.recipient !== "string" ||
    typeof proposal.amountYocto !== "string" ||
    typeof proposal.asset !== "string" ||
    !["ALLOW", "WARN", "BLOCK"].includes(String(data.decision)) ||
    typeof data.explanation !== "string" ||
    !isStringArray(data.triggeredPolicyRules) ||
    !isStringArray(data.checksPerformed) ||
    !["blocked", "warned", "allowed"].includes(String(data.outcome)) ||
    data.isSimulation !== true ||
    data.executed !== false ||
    typeof data.policyVersion !== "string" ||
    typeof data.createdAt !== "string" ||
    !Number.isFinite(Date.parse(data.createdAt))
  ) {
    throw new Error("SENTRA returned malformed Threat Lab simulation data.");
  }
  return {
    id: data.id,
    agentId: expectedAgentId,
    scenarioId: data.scenarioId,
    description: data.description,
    maliciousInstruction: data.maliciousInstruction,
    simulatedResponse: data.simulatedResponse,
    proposedTransaction: {
      network: proposal.network,
      transactionType: proposal.transactionType,
      recipient: proposal.recipient,
      amountYocto: proposal.amountYocto,
      asset: proposal.asset,
    },
    checksPerformed: data.checksPerformed,
    decision: data.decision as TransactionDecision,
    explanation: data.explanation,
    triggeredPolicyRules: data.triggeredPolicyRules,
    outcome: data.outcome as ThreatSimulation["outcome"],
    isSimulation: true,
    executed: false,
    policyVersion: data.policyVersion,
    createdAt: new Date(data.createdAt).toISOString(),
  };
}

function findAuditEvent(payload: unknown, simulationId: string): ThreatAuditEvent | null {
  if (!isRecord(payload) || !Array.isArray(payload.data)) return null;
  const event = payload.data.find((item) =>
    isRecord(item) &&
    item.entityId === simulationId &&
    item.eventType === "threat_lab.simulation.completed" &&
    isRecord(item.details)
  );
  if (
    !isRecord(event) ||
    typeof event.id !== "string" ||
    event.eventType !== "threat_lab.simulation.completed" ||
    event.entityId !== simulationId ||
    typeof event.createdAt !== "string" ||
    !isRecord(event.details) ||
    !Number.isFinite(Date.parse(event.createdAt))
  ) {
    return null;
  }
  return {
    id: event.id,
    eventType: "threat_lab.simulation.completed",
    entityId: simulationId,
    createdAt: new Date(event.createdAt).toISOString(),
    details: event.details,
  };
}

export async function runThreatSimulation(
  agentId: string,
  scenarioId: ThreatScenario["id"],
  fetchImplementation: typeof fetch = fetch,
): Promise<ThreatSimulationResult> {
  if (typeof agentId !== "string" || agentId.trim().length === 0 || !isScenarioId(scenarioId)) {
    throw new Error("Select a registered agent and a supported Threat Lab scenario.");
  }
  const response = await authenticatedApiFetch("/api/threat-lab/simulate", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({ agentId, scenarioId }),
  }, fetchImplementation);
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid Threat Lab simulation response.");
  }
  if (!response.ok) {
    throw new Error(apiError(payload, "SENTRA could not run this Threat Lab simulation."));
  }
  const simulation = parseSimulation(payload, agentId);

  let auditEvent: ThreatAuditEvent | null = null;
  try {
    const auditResponse = await authenticatedApiFetch("/api/audit", {
      method: "GET",
      headers: { accept: "application/json" },
      cache: "no-store",
    }, fetchImplementation);
    if (auditResponse.ok) {
      auditEvent = findAuditEvent(await auditResponse.json(), simulation.id);
    }
  } catch {
    auditEvent = null;
  }
  return { simulation, auditEvent };
}
