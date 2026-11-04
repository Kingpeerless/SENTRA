import assert from "node:assert/strict";
import test from "node:test";
import { verifyTestnetAccount } from "./nearAccountVerification.ts";

const ACCOUNT_ID = "sentra-agent.testnet";
const RPC_ID = "sentra-testnet-account-verification";

function response(payload, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function accountResponse(id = RPC_ID) {
  return response({
    jsonrpc: "2.0",
    id,
    result: {
      amount: "1000000000000000000000000",
      locked: "0",
      code_hash: "11111111111111111111111111111111",
      storage_usage: 182,
    },
  });
}

test("verifies account presence using a read-only Testnet RPC query", async () => {
  let requestUrl = "";
  let requestInit;
  const result = await verifyTestnetAccount(ACCOUNT_ID, async (input, init) => {
    requestUrl = String(input);
    requestInit = init;
    return accountResponse();
  });

  assert.equal(result.accountStatus, "verified");
  assert.equal(result.networkStatus, "unverified");
  assert.equal(requestUrl, "https://test.rpc.fastnear.com");
  assert.equal(requestInit.method, "POST");
  assert.equal(requestInit.redirect, "error");
  assert.deepEqual(JSON.parse(String(requestInit.body)), {
    jsonrpc: "2.0",
    id: RPC_ID,
    method: "query",
    params: {
      request_type: "view_account",
      finality: "final",
      account_id: ACCOUNT_ID,
    },
  });
});

test("a Testnet lookup failure does not infer a wallet network or verify mainnet-only accounts", async () => {
  const result = await verifyTestnetAccount(ACCOUNT_ID, async () =>
    response({
      jsonrpc: "2.0",
      id: RPC_ID,
      error: {
        name: "HANDLER_ERROR",
        cause: { name: "AccountDoesNotExist" },
      },
    }),
  );

  assert.equal(result.accountStatus, "missing");
  assert.equal(result.networkStatus, "unverified");
  assert.match(result.message, /not found on NEAR Testnet/);
});

test("reports a missing account separately from an unverified wallet network", async () => {
  const result = await verifyTestnetAccount("missing.testnet", async () =>
    response({
      jsonrpc: "2.0",
      id: RPC_ID,
      error: { name: "AccountDoesNotExist" },
    }),
  );

  assert.equal(result.accountStatus, "missing");
  assert.equal(result.networkStatus, "unverified");
});

test("RPC failures leave account and network verification unverified", async () => {
  const result = await verifyTestnetAccount(ACCOUNT_ID, async () => {
    throw new TypeError("network unavailable");
  });

  assert.equal(result.accountStatus, "unverified");
  assert.equal(result.networkStatus, "unverified");
});

test("account changes during an RPC lookup make its result stale", async () => {
  let currentAccount = ACCOUNT_ID;
  let resolveResponse;
  const pendingResponse = new Promise((resolve) => {
    resolveResponse = resolve;
  });

  const pending = verifyTestnetAccount(
    ACCOUNT_ID,
    async () => pendingResponse,
    () => currentAccount === ACCOUNT_ID,
  );
  currentAccount = "changed-account.testnet";
  resolveResponse(accountResponse());

  const result = await pending;
  assert.equal(result.accountStatus, "stale");
  assert.equal(result.networkStatus, "unverified");
});
