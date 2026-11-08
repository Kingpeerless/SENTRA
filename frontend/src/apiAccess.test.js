import assert from "node:assert/strict";
import test from "node:test";
import {
  authenticatedApiFetch,
  clearAccessToken,
  setAccessToken,
  verifyAccessToken,
} from "./apiAccess.ts";

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

test("access screen verification sends the entered bearer token and accepts authenticated response", async () => {
  let requestUrl = "";
  let requestOptions;
  const valid = await verifyAccessToken("operator-token", async (url, options) => {
    requestUrl = String(url);
    requestOptions = options;
    return jsonResponse({ data: { authenticated: true } });
  });

  assert.equal(valid, true);
  assert.equal(requestUrl, "/api/auth/verify");
  assert.equal(requestOptions.headers.authorization, "Bearer operator-token");
  assert.equal(requestOptions.cache, "no-store");
});

test("access screen rejects invalid tokens and malformed verification responses", async () => {
  assert.equal(
    await verifyAccessToken("wrong-token", async () => jsonResponse({
      error: { code: "UNAUTHORIZED" },
    }, 401)),
    false,
  );
  assert.equal(
    await verifyAccessToken("operator-token", async () => jsonResponse({
      data: { authenticated: false },
    })),
    false,
  );
});

test("authenticated API requests carry the in-memory bearer token and logout clears it", async () => {
  let authorization;
  setAccessToken("operator-token");
  try {
    await authenticatedApiFetch("/api/agents", {}, async (_url, options) => {
      authorization = options.headers.get("authorization");
      return jsonResponse({ data: [] });
    });
    assert.equal(authorization, "Bearer operator-token");
  } finally {
    clearAccessToken();
  }

  await assert.rejects(
    authenticatedApiFetch("/api/agents", {}, async () => jsonResponse({ data: [] })),
    /access session is unavailable/,
  );
});
