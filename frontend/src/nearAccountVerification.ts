const TESTNET_RPC_URL = "https://test.rpc.fastnear.com";
const RPC_REQUEST_ID = "sentra-testnet-account-verification";
const ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

export type TestnetAccountStatus =
  | "verified"
  | "missing"
  | "unverified"
  | "stale"
  | "invalid";

export interface TestnetAccountVerification {
  accountStatus: TestnetAccountStatus;
  networkStatus: "unverified";
  message: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isValidAccountId(accountId: string): boolean {
  return accountId.length >= 2 && accountId.length <= 64 && ACCOUNT_ID_PATTERN.test(accountId);
}

function isViewAccountResult(value: unknown): boolean {
  return (
    isRecord(value) &&
    typeof value.amount === "string" &&
    /^\d+$/.test(value.amount) &&
    typeof value.locked === "string" &&
    /^\d+$/.test(value.locked) &&
    typeof value.code_hash === "string" &&
    typeof value.storage_usage === "number" &&
    Number.isSafeInteger(value.storage_usage) &&
    value.storage_usage >= 0
  );
}

function isAccountMissing(error: unknown): boolean {
  if (!isRecord(error)) return false;
  const causeName =
    isRecord(error.cause) && typeof error.cause.name === "string"
      ? error.cause.name
      : null;
  return error.name === "AccountDoesNotExist" || causeName === "AccountDoesNotExist";
}

function result(
  accountStatus: TestnetAccountStatus,
  message: string,
): TestnetAccountVerification {
  return { accountStatus, networkStatus: "unverified", message };
}

export async function verifyTestnetAccount(
  accountId: string,
  fetchImplementation: typeof fetch = fetch,
  isCurrent: () => boolean = () => true,
): Promise<TestnetAccountVerification> {
  if (!isValidAccountId(accountId)) {
    return result("invalid", "The connected wallet returned an invalid NEAR account ID.");
  }

  let response: Response;
  try {
    response = await fetchImplementation(TESTNET_RPC_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: AbortSignal.timeout(8000),
      redirect: "error",
      body: JSON.stringify({
        jsonrpc: "2.0",
        id: RPC_REQUEST_ID,
        method: "query",
        params: {
          request_type: "view_account",
          finality: "final",
          account_id: accountId,
        },
      }),
    });
  } catch {
    return isCurrent()
      ? result("unverified", "The Testnet account lookup failed; account presence is unverified.")
      : result("stale", "The wallet account changed while verification was in progress.");
  }

  if (!isCurrent()) {
    return result("stale", "The wallet account changed while verification was in progress.");
  }
  if (!response.ok) {
    return result(
      "unverified",
      `The Testnet RPC returned HTTP ${response.status}; account presence is unverified.`,
    );
  }

  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return result("unverified", "The Testnet RPC returned invalid JSON.");
  }
  if (!isCurrent()) {
    return result("stale", "The wallet account changed while verification was in progress.");
  }
  if (
    !isRecord(payload) ||
    payload.jsonrpc !== "2.0" ||
    payload.id !== RPC_REQUEST_ID
  ) {
    return result("unverified", "The Testnet RPC response was malformed.");
  }
  if (payload.error !== undefined) {
    return isAccountMissing(payload.error)
      ? result("missing", "This account was not found on NEAR Testnet.")
      : result("unverified", "The Testnet RPC could not verify this account.");
  }
  if (!isViewAccountResult(payload.result)) {
    return result("unverified", "The Testnet RPC returned incomplete account data.");
  }
  return result(
    "verified",
    "This account exists on NEAR Testnet. The wallet's active network remains unverified.",
  );
}
