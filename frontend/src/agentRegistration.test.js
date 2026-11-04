import assert from "node:assert/strict";
import test from "node:test";
import { registerAgent } from "./agentRegistration.ts";

const createdAgent = {
  id: "agent-123",
  name: "Sentra Treasury",
  authorizedNearAccountId: null,
};

function jsonResponse(payload, status = 201) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("registers an agent through the existing API with trimmed name and description", async () => {
  let requestUrl = "";
  let requestInit;
  const agent = await registerAgent(
    { name: "  Sentra Treasury  ", description: "Treasury operator" },
    async (input, init) => {
      requestUrl = String(input);
      requestInit = init;
      return jsonResponse({ data: { agent: createdAgent, policy: {} } });
    },
  );

  assert.equal(requestUrl, "/api/agents");
  assert.equal(requestInit.method, "POST");
  assert.deepEqual(JSON.parse(requestInit.body), {
    name: "Sentra Treasury",
    description: "Treasury operator",
  });
  assert.deepEqual(agent, createdAgent);
  assert.equal(agent.authorizedNearAccountId, null);
});

test("rejects invalid client-side name and description without sending a request", async () => {
  let fetchCalls = 0;
  const fetchImplementation = async () => {
    fetchCalls += 1;
    return jsonResponse({ data: { agent: createdAgent } });
  };

  await assert.rejects(
    registerAgent({ name: "   ", description: "" }, fetchImplementation),
    /Agent name must be between 1 and 120 characters/,
  );
  await assert.rejects(
    registerAgent({ name: "a".repeat(121), description: "" }, fetchImplementation),
    /Agent name must be between 1 and 120 characters/,
  );
  await assert.rejects(
    registerAgent({ name: "Valid", description: "x".repeat(2001) }, fetchImplementation),
    /Description must be 2000 characters or fewer/,
  );
  assert.equal(fetchCalls, 0);
});

test("shows backend validation errors", async () => {
  await assert.rejects(
    registerAgent({ name: "Valid", description: "" }, async () =>
      jsonResponse({
        error: {
          code: "INVALID_INPUT",
          message: "Request validation failed.",
        },
      }, 400),
    ),
    /Request validation failed/,
  );
});

test("rejects malformed agent creation responses", async () => {
  await assert.rejects(
    registerAgent({ name: "Valid", description: "" }, async () =>
      jsonResponse({ data: { agent: { id: "missing-fields" } } }),
    ),
    /malformed agent registration data/,
  );
});
