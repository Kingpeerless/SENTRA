const DEFAULT_TESTNET_RPC_URL = "https://test.rpc.fastnear.com";
const ALLOWED_TESTNET_RPC_ENDPOINTS = new Set([
  "https://test.rpc.fastnear.com/",
  "https://archival-rpc.testnet.near.org/",
]);
const ACCOUNT_ID_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const TRANSACTION_HASH_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{43,44}$/;
const YOCTO_AMOUNT_PATTERN = /^\d+$/;
const RPC_REQUEST_ID = "sentra-testnet-transaction-verification";

export type TransactionVerificationStatus = "verified" | "failed" | "unverified";

export interface VerificationReason {
  code: string;
  message: string;
}

export interface NearTransactionExpectation {
  transactionHash: string;
  signerAccountId: string;
  receiverAccountId: string;
  amountYocto: string;
}

export interface NearTransactionVerification {
  status: TransactionVerificationStatus;
  verified: boolean;
  transactionHash: string;
  finality: string | null;
  reasons: VerificationReason[];
  observed: {
    signerAccountId: string;
    receiverAccountId: string;
    actionCount: number;
    actionType: string | null;
    amountYocto: string | null;
  } | null;
}

export interface NearTestnetVerifierOptions {
  rpcUrl?: string;
  timeoutMs?: number;
  fetchImplementation?: typeof fetch;
}

interface RpcResponse {
  jsonrpc?: unknown;
  id?: unknown;
  result?: unknown;
  error?: unknown;
}

interface RpcTransaction {
  hash?: unknown;
  signer_id?: unknown;
  receiver_id?: unknown;
  actions?: unknown;
}

interface RpcOutcome {
  final_execution_status?: unknown;
  status?: unknown;
  transaction?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function validAccountId(value: string): boolean {
  return value.length >= 2 && value.length <= 64 && ACCOUNT_ID_PATTERN.test(value);
}

function validPositiveYoctoAmount(value: string): boolean {
  return YOCTO_AMOUNT_PATTERN.test(value) && BigInt(value) > 0n;
}

function validateRpcUrl(value: string): string {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("NEAR_TESTNET_RPC_URL must be a documented HTTPS testnet RPC endpoint.");
  }

  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    !ALLOWED_TESTNET_RPC_ENDPOINTS.has(url.origin + url.pathname)
  ) {
    throw new Error(
      "NEAR_TESTNET_RPC_URL must be https://test.rpc.fastnear.com or https://archival-rpc.testnet.near.org.",
    );
  }
  return url.toString();
}

function result(
  expectation: NearTransactionExpectation,
  status: TransactionVerificationStatus,
  code: string,
  message: string,
  finality: string | null = null,
  observed: NearTransactionVerification["observed"] = null,
): NearTransactionVerification {
  return {
    status,
    verified: status === "verified",
    transactionHash: expectation.transactionHash,
    finality,
    reasons: [{ code, message }],
    observed,
  };
}

function validateExpectation(
  expectation: NearTransactionExpectation,
): VerificationReason | null {
  if (!TRANSACTION_HASH_PATTERN.test(expectation.transactionHash)) {
    return {
      code: "INVALID_TRANSACTION_HASH",
      message: "Transaction hash must be a valid NEAR base58 hash.",
    };
  }
  if (!validAccountId(expectation.signerAccountId)) {
    return {
      code: "INVALID_SIGNER_ACCOUNT",
      message: "Expected signer must be a valid NEAR account ID.",
    };
  }
  if (!validAccountId(expectation.receiverAccountId)) {
    return {
      code: "INVALID_RECEIVER_ACCOUNT",
      message: "Expected receiver must be a valid NEAR account ID.",
    };
  }
  if (!validPositiveYoctoAmount(expectation.amountYocto)) {
    return {
      code: "INVALID_AMOUNT",
      message: "Expected amount must be a positive integer yoctoNEAR string.",
    };
  }
  return null;
}

export class NearTestnetTransactionVerifier {
  private readonly rpcUrl: string;
  private readonly timeoutMs: number;
  private readonly fetchImplementation: typeof fetch;

  constructor(options: NearTestnetVerifierOptions = {}) {
    this.rpcUrl = validateRpcUrl(
      options.rpcUrl ?? process.env.NEAR_TESTNET_RPC_URL ?? DEFAULT_TESTNET_RPC_URL,
    );
    this.timeoutMs = options.timeoutMs ?? 10_000;
    if (!Number.isSafeInteger(this.timeoutMs) || this.timeoutMs <= 0) {
      throw new Error("NEAR RPC timeout must be a positive safe integer in milliseconds.");
    }
    this.fetchImplementation = options.fetchImplementation ?? fetch;
  }

  async verify(
    expectation: NearTransactionExpectation,
  ): Promise<NearTransactionVerification> {
    const invalidExpectation = validateExpectation(expectation);
    if (invalidExpectation) {
      return result(
        expectation,
        "unverified",
        invalidExpectation.code,
        invalidExpectation.message,
      );
    }

    let response: Response;
    try {
      response = await this.fetchImplementation(this.rpcUrl, {
        method: "POST",
        headers: { "content-type": "application/json" },
        signal: AbortSignal.timeout(this.timeoutMs),
        redirect: "error",
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: RPC_REQUEST_ID,
          method: "tx",
          params: {
            tx_hash: expectation.transactionHash,
            sender_account_id: expectation.signerAccountId,
            wait_until: "FINAL",
          },
        }),
      });
    } catch (error) {
      const timedOut =
        error instanceof Error &&
        (error.name === "TimeoutError" || error.name === "AbortError");
      return result(
        expectation,
        "unverified",
        timedOut ? "RPC_TIMEOUT" : "RPC_UNAVAILABLE",
        timedOut
          ? "NEAR RPC verification timed out; transaction outcome remains unverified."
          : "NEAR RPC could not be reached; transaction outcome remains unverified.",
      );
    }

    if (!response.ok) {
      return result(
        expectation,
        "unverified",
        "RPC_HTTP_ERROR",
        `NEAR testnet RPC returned HTTP ${response.status}; transaction outcome remains unverified.`,
      );
    }

    let payload: RpcResponse;
    try {
      payload = (await response.json()) as RpcResponse;
    } catch {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "NEAR RPC response was not valid JSON; transaction outcome remains unverified.",
      );
    }

    if (
      !isRecord(payload) ||
      payload.jsonrpc !== "2.0" ||
      payload.id !== RPC_REQUEST_ID
    ) {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "NEAR RPC response did not match the expected JSON-RPC envelope.",
      );
    }

    if (payload.error !== undefined) {
      const errorName =
        isRecord(payload.error) && typeof payload.error.name === "string"
          ? payload.error.name
          : null;
      const causeName =
        isRecord(payload.error) &&
        isRecord(payload.error.cause) &&
        typeof payload.error.cause.name === "string"
          ? payload.error.cause.name
          : null;
      const rpcError = causeName ?? errorName;
      return result(
        expectation,
        "unverified",
        rpcError === "UNKNOWN_TRANSACTION" ? "TRANSACTION_UNKNOWN" : "RPC_ERROR",
        rpcError === "UNKNOWN_TRANSACTION"
          ? "NEAR testnet RPC does not currently know this transaction; outcome remains unverified."
          : "NEAR testnet RPC returned an error; transaction outcome remains unverified.",
      );
    }

    if (!isRecord(payload.result)) {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "NEAR RPC response did not contain a transaction result.",
      );
    }

    const outcome = payload.result as RpcOutcome;
    if (outcome.final_execution_status !== "FINAL") {
      const finality =
        typeof outcome.final_execution_status === "string"
          ? outcome.final_execution_status
          : null;
      return result(
        expectation,
        "unverified",
        "TRANSACTION_NOT_FINAL",
        "Transaction has not reached final execution; its outcome remains unverified.",
        finality,
      );
    }

    if (!isRecord(outcome.status)) {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "Final transaction result did not contain a valid execution status.",
        "FINAL",
      );
    }

    if ("Failure" in outcome.status) {
      return result(
        expectation,
        "failed",
        "TRANSACTION_FAILED",
        "NEAR testnet reports that the finalized transaction failed.",
        "FINAL",
      );
    }

    if (typeof outcome.status.SuccessValue !== "string" || outcome.status.SuccessValue !== "") {
      return result(
        expectation,
        "unverified",
        "TRANSACTION_STATUS_INDETERMINATE",
        "Final transaction status was not the expected successful native-transfer result.",
        "FINAL",
      );
    }

    if (!isRecord(outcome.transaction)) {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "Final transaction result did not contain a transaction.",
        "FINAL",
      );
    }

    const transaction = outcome.transaction as RpcTransaction;
    if (
      typeof transaction.hash !== "string" ||
      typeof transaction.signer_id !== "string" ||
      typeof transaction.receiver_id !== "string" ||
      !Array.isArray(transaction.actions)
    ) {
      return result(
        expectation,
        "unverified",
        "MALFORMED_RPC_RESPONSE",
        "Final transaction is missing its hash, signer, receiver, or actions.",
        "FINAL",
      );
    }

    const actionCount = transaction.actions.length;
    const rawAction = actionCount === 1 ? transaction.actions[0] : undefined;
    const actionIsOnlyTransfer =
      isRecord(rawAction) &&
      Object.keys(rawAction).length === 1 &&
      isRecord(rawAction.Transfer) &&
      Object.keys(rawAction.Transfer).length === 1 &&
      typeof rawAction.Transfer.deposit === "string" &&
      YOCTO_AMOUNT_PATTERN.test(rawAction.Transfer.deposit);
    const observed = {
      signerAccountId: transaction.signer_id,
      receiverAccountId: transaction.receiver_id,
      actionCount,
      actionType: isRecord(rawAction) ? Object.keys(rawAction)[0] ?? null : null,
      amountYocto:
        actionIsOnlyTransfer && isRecord(rawAction) && isRecord(rawAction.Transfer)
          ? rawAction.Transfer.deposit as string
          : null,
    };

    if (transaction.hash !== expectation.transactionHash) {
      return result(
        expectation,
        "unverified",
        "TRANSACTION_HASH_MISMATCH",
        "NEAR RPC returned a different transaction hash than requested.",
        "FINAL",
        observed,
      );
    }
    if (transaction.signer_id !== expectation.signerAccountId) {
      return result(
        expectation,
        "unverified",
        "SIGNER_MISMATCH",
        "Final transaction signer does not match the expected signer.",
        "FINAL",
        observed,
      );
    }
    if (transaction.receiver_id !== expectation.receiverAccountId) {
      return result(
        expectation,
        "unverified",
        "RECEIVER_MISMATCH",
        "Final transaction receiver does not match the expected receiver.",
        "FINAL",
        observed,
      );
    }
    if (actionCount !== 1) {
      return result(
        expectation,
        "unverified",
        "ACTION_COUNT_MISMATCH",
        "Final transaction must contain exactly one action.",
        "FINAL",
        observed,
      );
    }
    if (!actionIsOnlyTransfer || observed.amountYocto === null) {
      return result(
        expectation,
        "unverified",
        "UNSUPPORTED_ACTION",
        "Final transaction must contain exactly one native NEAR Transfer action.",
        "FINAL",
        observed,
      );
    }
    if (BigInt(observed.amountYocto) !== BigInt(expectation.amountYocto)) {
      return result(
        expectation,
        "unverified",
        "AMOUNT_MISMATCH",
        "Final native transfer amount does not match the expected yoctoNEAR amount.",
        "FINAL",
        observed,
      );
    }

    return result(
      expectation,
      "verified",
      "TRANSFER_VERIFIED",
      "NEAR testnet confirms the expected single-action native transfer succeeded at finality.",
      "FINAL",
      observed,
    );
  }
}
