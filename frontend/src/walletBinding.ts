export interface AgentWalletBinding {
  id: string;
  name: string;
  authorizedNearAccountId: string | null;
  enabled?: boolean;
}

export type WalletBindingStatus =
  | "MATCH"
  | "MISMATCH"
  | "NOT BOUND"
  | "WALLET DISCONNECTED";

export function getWalletBindingStatus(
  agent: AgentWalletBinding | null,
  connectedAccountId: string | null,
): WalletBindingStatus {
  if (!connectedAccountId) return "WALLET DISCONNECTED";
  if (!agent || !agent.authorizedNearAccountId) return "NOT BOUND";
  return agent.authorizedNearAccountId === connectedAccountId ? "MATCH" : "MISMATCH";
}

export function parseAgentsResponse(payload: unknown): AgentWalletBinding[] {
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("data" in payload) ||
    !Array.isArray(payload.data)
  ) {
    throw new Error("Agent API returned an invalid response.");
  }

  return payload.data.map((agent: unknown) => {
    const enabled = typeof agent === "object" && agent !== null && "enabled" in agent
      ? agent.enabled
      : undefined;
    if (
      typeof agent !== "object" ||
      agent === null ||
      !("id" in agent) ||
      typeof agent.id !== "string" ||
      !("name" in agent) ||
      typeof agent.name !== "string" ||
      !("authorizedNearAccountId" in agent) ||
      (agent.authorizedNearAccountId !== null &&
        typeof agent.authorizedNearAccountId !== "string") ||
        (enabled !== undefined && typeof enabled !== "boolean")
    ) {
      throw new Error("Agent API returned malformed agent data.");
    }

    return {
      id: agent.id,
      name: agent.name,
      authorizedNearAccountId: agent.authorizedNearAccountId,
      ...(typeof enabled === "boolean" ? { enabled } : {}),
    };
  });
}
