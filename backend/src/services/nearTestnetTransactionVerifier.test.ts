import assert from "node:assert/strict";
import test from "node:test";
import {
  NearTestnetTransactionVerifier,
  type NearTransactionExpectation,
} from "./nearTestnetTransactionVerifier.js";

const rpcUrl = "https://test.rpc.fastnear.com";
const expectation: NearTransactionExpectation = {
  transactionHash: "6zgh2u9DqHHiXzdy9ouTP7oGky2T4nugbhqsK7wQHnZS",
  signerAccountId: "sender.testnet",
  receiverAccountId: "receiver.testnet",
  amountYocto: "1234567890123456789012345",
};

function successResponse(overrides: {
  finality?: unknown;
  status?: unknown;
  hash?: unknown;
  signer?: unknown;
  receiver?: unknown;
  actions?: unknown;
} = {}) {
  return {
    jsonrpc: "2.0",
    id: "sentra-testnet-transaction-verification",
    result: {
      final_execution_status: overrides.finality ?? "FINAL",
      status: overrides.status ?? { SuccessValue: "" },
      transaction: {
        hash: overrides.hash ?? expectation.transactionHash,
        signer_id: overrides.signer ?? expectation.signerAccountId,
        receiver_id: overrides.receiver ?? expectation.receiverAccountId,
        actions: overrides.actions ?? [
          { Transfer: { deposit: expectation.amountYocto } },
        ],
      },
    },
  };
}

function mockFetchFor(payload: unknown): typeof fetch {
  return async () =>
    new Response(JSON.stringify(payload), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
}

function verifier(fetchImplementation: typeof fetch) {
  return new NearTestnetTransactionVerifier({ rpcUrl, fetchImplementation });
}

test("verifies a finalized successful native NEAR transfer", async () => {
  const instance = verifier(mockFetchFor(successResponse()));
  const result = await instance.verify(expectation);

  assert.equal(result.status, "verified");
  assert.equal(result.verified, true);
  assert.equal(result.finality, "FINAL");
  assert.equal(result.reasons[0]?.code, "TRANSFER_VERIFIED");
  assert.deepEqual(result.observed, {
    signerAccountId: expectation.signerAccountId,
    receiverAccountId: expectation.receiverAccountId,
    actionCount: 1,
    actionType: "Transfer",
    amountYocto: expectation.amountYocto,
  });
});

test("reports a finalized failed transaction as failed", async () => {
  const instance = verifier(
    mockFetchFor(successResponse({ status: { Failure: { error: "failure" } } })),
  );
  const result = await instance.verify(expectation);

  assert.equal(result.status, "failed");
  assert.equal(result.verified, false);
  assert.equal(result.reasons[0]?.code, "TRANSACTION_FAILED");
});

test("rejects a signer mismatch", async () => {
  const result = await verifier(mockFetchFor(successResponse({ signer: "other.testnet" })))
    .verify(expectation);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "SIGNER_MISMATCH");
});

test("rejects a receiver mismatch", async () => {
  const result = await verifier(
    mockFetchFor(successResponse({ receiver: "other.testnet" })),
  ).verify(expectation);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "RECEIVER_MISMATCH");
});

test("rejects an amount mismatch using exact integer comparison", async () => {
  const result = await verifier(
    mockFetchFor(
      successResponse({
        actions: [{ Transfer: { deposit: "1234567890123456789012346" } }],
      }),
    ),
  ).verify(expectation);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "AMOUNT_MISMATCH");
});

test("rejects multiple transaction actions", async () => {
  const result = await verifier(
    mockFetchFor(
      successResponse({
        actions: [
          { Transfer: { deposit: expectation.amountYocto } },
          { CreateAccount: {} },
        ],
      }),
    ),
  ).verify(expectation);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "ACTION_COUNT_MISMATCH");
});

test("rejects a non-transfer action", async () => {
  const result = await verifier(
    mockFetchFor(
      successResponse({ actions: [{ FunctionCall: { deposit: "0" } }] }),
    ),
  ).verify(expectation);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "UNSUPPORTED_ACTION");
});

test("treats pending or unknown finality as unverified", async () => {
  const pending = await verifier(
    mockFetchFor(successResponse({ finality: "EXECUTED_OPTIMISTIC" })),
  ).verify(expectation);
  const unknown = await verifier(
    mockFetchFor(successResponse({ status: { Unknown: null } })),
  ).verify(expectation);

  assert.equal(pending.status, "unverified");
  assert.equal(pending.reasons[0]?.code, "TRANSACTION_NOT_FINAL");
  assert.equal(unknown.status, "unverified");
  assert.equal(unknown.reasons[0]?.code, "TRANSACTION_STATUS_INDETERMINATE");
});

test("treats malformed RPC response as unverified", async () => {
  const invalidJsonFetch: typeof fetch = async () =>
    new Response("{invalid", { status: 200 });
  const result = await verifier(invalidJsonFetch).verify(expectation);

  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "MALFORMED_RPC_RESPONSE");
});

test("treats RPC errors and unknown transactions as unverified", async () => {
  const errorFetch = mockFetchFor({
    jsonrpc: "2.0",
    id: "sentra-testnet-transaction-verification",
    error: {
      name: "HANDLER_ERROR",
      cause: { name: "UNKNOWN_TRANSACTION" },
    },
  });
  const unknown = await verifier(errorFetch).verify(expectation);
  const genericError = await verifier(
    mockFetchFor({
      jsonrpc: "2.0",
      id: "sentra-testnet-transaction-verification",
      error: { name: "INTERNAL_ERROR" },
    }),
  ).verify(expectation);

  assert.equal(unknown.status, "unverified");
  assert.equal(unknown.reasons[0]?.code, "TRANSACTION_UNKNOWN");
  assert.equal(genericError.status, "unverified");
  assert.equal(genericError.reasons[0]?.code, "RPC_ERROR");
});

test("does not follow redirects to fabricate a verified result", async () => {
  let redirectPolicy: RequestRedirect | undefined;
  const redirectFetch: typeof fetch = async (_input, init) => {
    redirectPolicy = init?.redirect;
    if (redirectPolicy === "error") {
      throw new TypeError("fetch failed because redirect mode is error");
    }
    return new Response(JSON.stringify(successResponse()), { status: 200 });
  };
  const result = await verifier(redirectFetch).verify(expectation);

  assert.equal(redirectPolicy, "error");
  assert.equal(result.status, "unverified");
  assert.equal(result.verified, false);
  assert.equal(result.reasons[0]?.code, "RPC_UNAVAILABLE");
});

test("aborts an actually pending RPC fetch when the configured timeout expires", async () => {
  let observedSignal: AbortSignal | undefined;
  const timeoutFetch: typeof fetch = async (_input, init) => {
    const signal = init?.signal;
    if (!(signal instanceof AbortSignal)) {
      throw new Error("verifier did not provide an abort signal");
    }
    observedSignal = signal;
    return new Promise<Response>((_resolve, reject) => {
      signal.addEventListener("abort", () => reject(signal.reason), { once: true });
    });
  };
  const timeoutVerifier = new NearTestnetTransactionVerifier({
    rpcUrl,
    timeoutMs: 20,
    fetchImplementation: timeoutFetch,
  });
  // Keep Node's event loop alive while AbortSignal.timeout fires.
  const keepAlive = setTimeout(() => undefined, 1000);
  const timeout = await timeoutVerifier.verify(expectation).finally(() => {
    clearTimeout(keepAlive);
  });
  const unavailableFetch: typeof fetch = async () => {
    throw new TypeError("fetch failed");
  };
  const unavailable = await verifier(unavailableFetch).verify(expectation);

  assert.ok(observedSignal);
  assert.equal(observedSignal.aborted, true);
  assert.equal(timeout.status, "unverified");
  assert.equal(timeout.reasons[0]?.code, "RPC_TIMEOUT");
  assert.equal(unavailable.status, "unverified");
  assert.equal(unavailable.reasons[0]?.code, "RPC_UNAVAILABLE");
});

test("sends a read-only tx request using the FINAL wait_until level", async () => {
  let requestedUrl = "";
  let requestBody: Record<string, unknown> | undefined;
  const inspectingFetch: typeof fetch = async (input, init) => {
    requestedUrl = String(input);
    requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
    return new Response(JSON.stringify(successResponse()), { status: 200 });
  };

  await verifier(inspectingFetch).verify(expectation);

  assert.equal(requestedUrl, rpcUrl + "/");
  assert.equal(requestBody?.method, "tx");
  assert.deepEqual(requestBody?.params, {
    tx_hash: expectation.transactionHash,
    sender_account_id: expectation.signerAccountId,
    wait_until: "FINAL",
  });
});

test("rejects mainnet, arbitrary endpoints, and URL allowlist bypasses", () => {
  assert.throws(
    () => new NearTestnetTransactionVerifier({ rpcUrl: "https://rpc.mainnet.near.org" }),
    /must be https/,
  );
  assert.throws(
    () => new NearTestnetTransactionVerifier({ rpcUrl: "https://rpc.example.com" }),
    /must be https/,
  );
  assert.throws(
    () => new NearTestnetTransactionVerifier({ rpcUrl: "http://test.rpc.fastnear.com" }),
    /must be https/,
  );
  assert.throws(
    () =>
      new NearTestnetTransactionVerifier({
        rpcUrl: "https://user:password@test.rpc.fastnear.com",
      }),
    /must be https/,
  );
  assert.throws(
    () =>
      new NearTestnetTransactionVerifier({
        rpcUrl: "https://test.rpc.fastnear.com/?redirect=attacker",
      }),
    /must be https/,
  );
  assert.throws(
    () =>
      new NearTestnetTransactionVerifier({
        rpcUrl: "https://test.rpc.fastnear.com/#fragment",
      }),
    /must be https/,
  );
  assert.throws(
    () =>
      new NearTestnetTransactionVerifier({
        rpcUrl: "https://test.rpc.fastnear.com.attacker.example",
      }),
    /must be https/,
  );
  assert.throws(
    () =>
      new NearTestnetTransactionVerifier({
        rpcUrl: "https://test.rpc.fastnear.com:8443",
      }),
    /must be https/,
  );
});

test("invalid expected transaction details do not make an RPC request", async () => {
  let called = false;
  const inspectingFetch: typeof fetch = async () => {
    called = true;
    return new Response(JSON.stringify(successResponse()), { status: 200 });
  };
  const result = await verifier(inspectingFetch).verify({
    ...expectation,
    amountYocto: "1.5",
  });

  assert.equal(called, false);
  assert.equal(result.status, "unverified");
  assert.equal(result.reasons[0]?.code, "INVALID_AMOUNT");
});
