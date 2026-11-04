import type { AgentWalletBinding } from "./walletBinding";

export interface NewAgentInput {
  name: string;
  description: string;
}

function parseCreatedAgent(payload: unknown): AgentWalletBinding {
  if (
    typeof payload !== "object" ||
    payload === null ||
    !("data" in payload) ||
    typeof payload.data !== "object" ||
    payload.data === null ||
    !("agent" in payload.data) ||
    typeof payload.data.agent !== "object" ||
    payload.data.agent === null
  ) {
    throw new Error("SENTRA returned an invalid agent registration response.");
  }

  const agent = payload.data.agent;
  if (
    !("id" in agent) ||
    typeof agent.id !== "string" ||
    !("name" in agent) ||
    typeof agent.name !== "string" ||
    !("authorizedNearAccountId" in agent) ||
    (agent.authorizedNearAccountId !== null &&
      typeof agent.authorizedNearAccountId !== "string")
  ) {
    throw new Error("SENTRA returned malformed agent registration data.");
  }

  return {
    id: agent.id,
    name: agent.name,
    authorizedNearAccountId: agent.authorizedNearAccountId,
  };
}

export async function registerAgent(
  input: NewAgentInput,
  fetchImplementation: typeof fetch = fetch,
): Promise<AgentWalletBinding> {
  const name = input.name.trim();
  const description = input.description;
  if (name.length === 0 || name.length > 120) {
    throw new Error("Agent name must be between 1 and 120 characters.");
  }
  if (description.length > 2000) {
    throw new Error("Description must be 2000 characters or fewer.");
  }

  const response = await fetchImplementation("/api/agents", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    body: JSON.stringify({ name, description }),
  });

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    throw new Error("SENTRA returned an invalid response while registering the agent.");
  }
  if (!response.ok) {
    const message =
      typeof payload === "object" &&
      payload !== null &&
      "error" in payload &&
      typeof payload.error === "object" &&
      payload.error !== null &&
      "message" in payload.error &&
      typeof payload.error.message === "string"
        ? payload.error.message
        : "SENTRA could not register the agent.";
    throw new Error(message);
  }

  return parseCreatedAgent(payload);
}
