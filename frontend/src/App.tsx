import { useEffect, useRef, useState, type FormEvent } from "react";
import {
  ACCESS_TOKEN_EXPIRED_EVENT,
  authenticatedApiFetch,
  clearAccessToken,
  setAccessToken,
  verifyAccessToken,
} from "./apiAccess";
import {
  NearConnector,
  type Account,
  type NearWalletBase,
} from "@hot-labs/near-connect";
import {
  verifyTestnetAccount,
  type TestnetAccountVerification,
} from "./nearAccountVerification";
import {
  getWalletBindingStatus,
  parseAgentsResponse,
  type AgentWalletBinding,
} from "./walletBinding";
import { registerAgent } from "./agentRegistration";
import {
  canPrepareSavedTransaction,
  expireTemporaryAuthorizationToken,
  formatYoctoNear,
  getWarnApprovalStatus,
  prepareSavedTransaction,
  revokeAuthorizationIntent,
  storeTemporaryAuthorizationToken,
  takeTemporaryAuthorizationToken,
  type TemporaryTokenRef,
  type PreparedAuthorization,
  type PreparedAuthorizationResponse,
  type SavedApproval,
  type SavedTransaction,
  type TemporaryTokenClearReason,
} from "./transactionAuthorization";
import {
  loadTransactionReviewData,
  submitTransactionEvaluation,
  type TransactionEvaluation,
} from "./transactionComposer";
import {
  getPendingWarnApprovals,
  reviewWarnApproval,
  type ApprovalReviewAction,
} from "./transactionApproval";
import {
  loadThreatScenarios,
  runPublicThreatSimulation,
  runThreatSimulation,
  type PublicThreatSimulation,
  type ThreatScenario,
  type ThreatSimulationResult,
} from "./threatLab";

type WalletStatus = "disconnected" | "connecting" | "connected" | "disconnecting" | "error";
type AccountCheckStatus = "idle" | "checking" | TestnetAccountVerification["accountStatus"];

const connector = new NearConnector({
  network: "testnet",
  features: { testnet: true },
  autoConnect: false,
  footerBranding: null,
});

const accountIdPattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;

function isValidAccountId(accountId: string): boolean {
  return accountId.length >= 2 && accountId.length <= 64 && accountIdPattern.test(accountId);
}

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [accessTokenInput, setAccessTokenInput] = useState("");
  const [accessBusy, setAccessBusy] = useState(false);
  const [accessError, setAccessError] = useState<string | null>(null);
  const [status, setStatus] = useState<WalletStatus>("disconnected");
  const [accountId, setAccountId] = useState<string | null>(null);
  const [accountCheck, setAccountCheck] = useState<TestnetAccountVerification | null>(null);
  const [accountCheckStatus, setAccountCheckStatus] = useState<AccountCheckStatus>("idle");
  const [agents, setAgents] = useState<AgentWalletBinding[]>([]);
  const [selectedAgentId, setSelectedAgentId] = useState("");
  const [agentsLoading, setAgentsLoading] = useState(true);
  const [agentsError, setAgentsError] = useState<string | null>(null);
  const [registrationOpen, setRegistrationOpen] = useState(false);
  const [registrationName, setRegistrationName] = useState("");
  const [registrationDescription, setRegistrationDescription] = useState("");
  const [registrationBusy, setRegistrationBusy] = useState(false);
  const [registrationMessage, setRegistrationMessage] = useState<string | null>(null);
  const [registrationError, setRegistrationError] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [transactions, setTransactions] = useState<SavedTransaction[]>([]);
  const [approvals, setApprovals] = useState<SavedApproval[]>([]);
  const [approvalActionBusyId, setApprovalActionBusyId] = useState<string | null>(null);
  const [approvalFeedback, setApprovalFeedback] = useState<{
    approvalId: string;
    kind: "success" | "error";
    message: string;
  } | null>(null);
  const [rejectionReasons, setRejectionReasons] = useState<Record<string, string>>({});
  const [transactionsLoading, setTransactionsLoading] = useState(true);
  const [transactionsError, setTransactionsError] = useState<string | null>(null);
  const [selectedTransactionId, setSelectedTransactionId] = useState("");
  const [preparingTransactionId, setPreparingTransactionId] = useState<string | null>(null);
  const [preparationError, setPreparationError] = useState<string | null>(null);
  const [revocationNotice, setRevocationNotice] = useState<string | null>(null);
  const [preparedIntents, setPreparedIntents] = useState<Record<string, PreparedAuthorization>>({});
  const [authorizationTokenStates, setAuthorizationTokenStates] = useState<
    Record<
      string,
      "available" | "cleared" | "expired" | "not-retained" | "revoked" | "revocation-failed"
    >
  >({});
  const [activeAuthorizationTokenIntentId, setActiveAuthorizationTokenIntentId] =
    useState<string | null>(null);
  const [authorizationClock, setAuthorizationClock] = useState(() => Date.now());
  const [composerAgentId, setComposerAgentId] = useState("");
  const [composerRecipient, setComposerRecipient] = useState("");
  const [composerAmount, setComposerAmount] = useState("");
  const [evaluationBusy, setEvaluationBusy] = useState(false);
  const [evaluationError, setEvaluationError] = useState<string | null>(null);
  const [evaluationResult, setEvaluationResult] = useState<TransactionEvaluation | null>(null);
  const [threatLabScenarios, setThreatLabScenarios] = useState<ThreatScenario[]>([]);
  const [threatLabScenariosLoading, setThreatLabScenariosLoading] = useState(true);
  const [threatLabError, setThreatLabError] = useState<string | null>(null);
  const [threatLabAgentId, setThreatLabAgentId] = useState("");
  const [threatLabScenarioId, setThreatLabScenarioId] = useState("");
  const [threatLabBusy, setThreatLabBusy] = useState(false);
  const [threatLabResult, setThreatLabResult] = useState<ThreatSimulationResult | null>(null);
  const [publicDemoScenarioId, setPublicDemoScenarioId] = useState("");
  const [publicDemoBusy, setPublicDemoBusy] = useState(false);
  const [publicDemoError, setPublicDemoError] = useState<string | null>(null);
  const [publicDemoResult, setPublicDemoResult] = useState<PublicThreatSimulation | null>(null);
  const walletRef = useRef<NearWalletBase | null>(null);
  const accountIdRef = useRef<string | null>(null);
  const mountedRef = useRef(false);
  const refreshInProgressRef = useRef(false);
  const preparationInProgressRef = useRef(false);
  const evaluationInProgressRef = useRef(false);
  const transactionsRefreshSequenceRef = useRef(0);
  const authorizationTokenRef = useRef<TemporaryTokenRef["current"]>(null);
  const authorizationTokenGenerationRef = useRef(0);
  const selectedAgentIdRef = useRef(selectedAgentId);
  const selectedTransactionIdRef = useRef(selectedTransactionId);

  const handleAccessSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (accessBusy || accessTokenInput.length === 0) return;
    setAccessBusy(true);
    setAccessError(null);
    try {
      if (!await verifyAccessToken(accessTokenInput)) {
        setAccessError("The access token was not accepted.");
        return;
      }
      setAccessToken(accessTokenInput);
      setAccessTokenInput("");
      setIsAuthenticated(true);
    } catch (error) {
      setAccessError(
        error instanceof Error ? error.message : "SENTRA could not verify the access token.",
      );
    } finally {
      setAccessBusy(false);
    }
  };

  const handleLogout = () => {
    clearAuthorizationToken("session-ended");
    clearAccessToken();
    setAccessTokenInput("");
    setAccessError(null);
    setAgents([]);
    setTransactions([]);
    setApprovals([]);
    setThreatLabResult(null);
    setEvaluationResult(null);
    setPreparedIntents({});
    setAuthorizationTokenStates({});
    setActiveAuthorizationTokenIntentId(null);
    setIsAuthenticated(false);
  };

  const clearAuthorizationToken = (reason: TemporaryTokenClearReason): string | null => {
    authorizationTokenGenerationRef.current += 1;
    const clearedToken = takeTemporaryAuthorizationToken(authorizationTokenRef, reason);
    const clearedIntentId = clearedToken?.intentId ?? null;
    if (clearedIntentId) {
      setAuthorizationTokenStates((current) => ({
        ...current,
        [clearedIntentId]: reason === "expired" ? "expired" : "cleared",
      }));
      setActiveAuthorizationTokenIntentId((current) =>
        current === clearedIntentId ? null : current,
      );
    }
    if (
      clearedToken &&
      ["wallet-disconnected", "account-changed", "agent-changed", "intent-replaced"].includes(reason)
    ) {
      setRevocationNotice(null);
      void revokeAuthorizationIntent(clearedToken.intentId, clearedToken.token)
        .then(() => {
          setAuthorizationTokenStates((current) => ({
            ...current,
            [clearedToken.intentId]: "revoked",
          }));
        })
        .catch(() => {
          setAuthorizationTokenStates((current) => ({
            ...current,
            [clearedToken.intentId]: "revocation-failed",
          }));
          setRevocationNotice(
            `SENTRA could not confirm revocation of intent ${clearedToken.intentId}. It may remain valid until ${new Date(clearedToken.expiresAt).toLocaleString()}. No automatic retry will be made.`,
          );
        });
    }
    return clearedIntentId;
  };

  const expireAuthorizationToken = () => {
    const expiredIntentId = expireTemporaryAuthorizationToken(authorizationTokenRef);
    if (!expiredIntentId) return;
    authorizationTokenGenerationRef.current += 1;
    setAuthorizationTokenStates((current) => ({
      ...current,
      [expiredIntentId]: "expired",
    }));
    setActiveAuthorizationTokenIntentId((current) =>
      current === expiredIntentId ? null : current,
    );
  };

  useEffect(() => {
    const handleExpiredAccessToken = () => {
      clearAuthorizationToken("session-ended");
      clearAccessToken();
      setAccessTokenInput("");
      setAccessError("Your access session expired. Enter the token again.");
      setIsAuthenticated(false);
    };
    window.addEventListener(ACCESS_TOKEN_EXPIRED_EVENT, handleExpiredAccessToken);
    return () => {
      window.removeEventListener(ACCESS_TOKEN_EXPIRED_EVENT, handleExpiredAccessToken);
    };
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    const clearConnection = () => {
      clearAuthorizationToken("wallet-disconnected");
      walletRef.current = null;
      accountIdRef.current = null;
      setAccountId(null);
      setAccountCheck(null);
      setAccountCheckStatus("idle");
      setStatus("disconnected");
    };

    const acceptAccounts = (wallet: NearWalletBase, accounts: Account[]) => {
      const connectedAccount = accounts[0]?.accountId;
      if (!connectedAccount || !isValidAccountId(connectedAccount)) {
        clearAuthorizationToken("account-changed");
        walletRef.current = null;
        accountIdRef.current = null;
        setAccountId(null);
        setAccountCheck(null);
        setAccountCheckStatus("idle");
        setStatus("error");
        setErrorMessage("The connected wallet returned an invalid NEAR account ID.");
        return;
      }

      if (accountIdRef.current !== connectedAccount) {
        clearAuthorizationToken("account-changed");
      }
      walletRef.current = wallet;
      accountIdRef.current = connectedAccount;
      setAccountId(connectedAccount);
      setStatus("connected");
      setErrorMessage(null);
    };

    const handleSignIn = (event: {
      wallet: NearWalletBase;
      accounts: Account[];
      success: boolean;
    }) => {
      if (!event.success) {
        clearConnection();
        setErrorMessage("Wallet connection was not completed.");
        return;
      }
      acceptAccounts(event.wallet, event.accounts);
    };

    const handleSignOut = () => {
      clearConnection();
    };

    connector.on("wallet:signIn", handleSignIn);
    connector.on("wallet:signOut", handleSignOut);

    const refreshAccount = async () => {
      const wallet = walletRef.current;
      if (!wallet || refreshInProgressRef.current) return;
      refreshInProgressRef.current = true;
      const currentWallet = wallet;
      try {
        const accounts = await currentWallet.getAccounts({ network: "testnet" });
        if (mountedRef.current && walletRef.current === currentWallet) {
          acceptAccounts(currentWallet, accounts);
        }
      } catch {
        if (mountedRef.current && walletRef.current === currentWallet) {
          clearConnection();
          setErrorMessage("The wallet session is no longer available. Connect again to continue.");
        }
      } finally {
        refreshInProgressRef.current = false;
      }
    };

    const intervalId = window.setInterval(() => {
      void refreshAccount();
    }, 3000);
    window.addEventListener("focus", refreshAccount);

    return () => {
      clearAuthorizationToken("session-ended");
      mountedRef.current = false;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", refreshAccount);
      connector.off("wallet:signIn", handleSignIn);
      connector.off("wallet:signOut", handleSignOut);
    };
  }, [isAuthenticated]);

  useEffect(() => {
    if (!accountId) {
      setAccountCheck(null);
      setAccountCheckStatus("idle");
      return;
    }

    let active = true;
    setAccountCheck(null);
    setAccountCheckStatus("checking");
    void verifyTestnetAccount(
      accountId,
      fetch,
      () => active && accountIdRef.current === accountId,
    ).then((verification) => {
      if (!active || accountIdRef.current !== accountId) return;
      setAccountCheck(verification);
      setAccountCheckStatus(verification.accountStatus);
    });

    return () => {
      active = false;
    };
  }, [accountId]);

  const connectWallet = async () => {
    clearAuthorizationToken("wallet-disconnected");
    setStatus("connecting");
    setErrorMessage(null);
    try {
      const wallet = await connector.connect();
      const accounts = await wallet.getAccounts({ network: "testnet" });
      if (accounts.length === 0) {
        throw new Error("No account returned");
      }
      walletRef.current = wallet;
      const connectedAccount = accounts[0].accountId;
      if (!isValidAccountId(connectedAccount)) {
        throw new Error("Invalid account ID");
      }
      accountIdRef.current = connectedAccount;
      setAccountId(connectedAccount);
      setStatus("connected");
    } catch (error) {
      clearAuthorizationToken("wallet-disconnected");
      walletRef.current = null;
      accountIdRef.current = null;
      setAccountId(null);
      setAccountCheck(null);
      setAccountCheckStatus("idle");
      setStatus("disconnected");
      const message = error instanceof Error ? error.message : "";
      setErrorMessage(
        /reject|cancel|denied/i.test(message)
          ? "Wallet connection was cancelled or rejected."
          : "Could not connect to the wallet. Check that it supports NEAR Testnet and try again.",
      );
    }
  };

  const handleRegisterAgent = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setRegistrationBusy(true);
    setRegistrationError(null);
    setRegistrationMessage(null);

    try {
      const registeredAgent = await registerAgent({
        name: registrationName,
        description: registrationDescription,
      });
      clearAuthorizationToken("agent-changed");
      selectedAgentIdRef.current = registeredAgent.id;
      setAgents((current) => [
        registeredAgent,
        ...current.filter((agent) => agent.id !== registeredAgent.id),
      ]);
      setSelectedAgentId(registeredAgent.id);
      setThreatLabAgentId(registeredAgent.id);
      setRegistrationName("");
      setRegistrationDescription("");
      setRegistrationOpen(false);

      try {
        const response = await authenticatedApiFetch("/api/agents", {
          headers: { accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) throw new Error("Agent list refresh failed.");
        const records = parseAgentsResponse(await response.json());
        setAgents(records);
        selectedAgentIdRef.current = registeredAgent.id;
        setSelectedAgentId(registeredAgent.id);
        setThreatLabAgentId(registeredAgent.id);
        setAgentsError(null);
        setRegistrationMessage(
          `${registeredAgent.name} registered and selected. Its wallet remains unbound.`,
        );
      } catch {
        setRegistrationMessage(
          `${registeredAgent.name} registered and selected, but the agent list could not be refreshed.`,
        );
      }
    } catch (error) {
      setRegistrationError(
        error instanceof Error ? error.message : "Could not register the agent.",
      );
    } finally {
      setRegistrationBusy(false);
    }
  };

  const disconnectWallet = async () => {
    clearAuthorizationToken("wallet-disconnected");
    const wallet = walletRef.current;
    if (!wallet) {
      setStatus("disconnected");
      setAccountId(null);
      return;
    }
    setStatus("disconnecting");
    setErrorMessage(null);
    try {
      await connector.disconnect(wallet);
      walletRef.current = null;
      accountIdRef.current = null;
      setAccountId(null);
      setAccountCheck(null);
      setAccountCheckStatus("idle");
      setStatus("disconnected");
    } catch {
      setStatus("connected");
      setErrorMessage("Could not disconnect the wallet. Try again from the wallet or this page.");
    }
  };

  const connected = status === "connected" || status === "disconnecting";
  const busy = status === "connecting" || status === "disconnecting";
  const selectedAgent = agents.find((agent) => agent.id === selectedAgentId) ?? null;
  const enabledAgents = agents.filter((agent) => agent.enabled === true);
  const composerAgent = enabledAgents.find((agent) => agent.id === composerAgentId) ?? null;
  const bindingStatus = getWalletBindingStatus(selectedAgent, accountId);
  const selectedTransaction =
    transactions.find((transaction) => transaction.id === selectedTransactionId) ?? null;
  const transactionAgent = selectedTransaction
    ? agents.find((agent) => agent.id === selectedTransaction.agentId) ?? null
    : null;
  const transactionApprovalStatus = selectedTransaction
    ? getWarnApprovalStatus(selectedTransaction, approvals)
    : "missing";
  const pendingWarnApprovals = getPendingWarnApprovals(approvals, transactions);
  const threatLabAgent = agents.find((agent) => agent.id === threatLabAgentId) ?? null;
  const selectedThreatScenario =
    threatLabScenarios.find((scenario) => scenario.id === threatLabScenarioId) ?? null;
  const preparedIntent = selectedTransaction
    ? preparedIntents[selectedTransaction.id] ?? null
    : null;
  const selectedTransactionAmount = selectedTransaction
    ? formatYoctoNear(selectedTransaction.amountYocto)
    : null;
  const preparedIntentAmount = preparedIntent
    ? formatYoctoNear(preparedIntent.amountYocto)
    : null;
  const preparedIntentExpired =
    preparedIntent !== null && authorizationClock >= Date.parse(preparedIntent.expiresAt);
  const transactionCanPrepare = selectedTransaction !== null &&
    canPrepareSavedTransaction(selectedTransaction, transactionApprovalStatus) &&
    transactionAgent !== null &&
    transactionAgent.authorizedNearAccountId !== null &&
    transactionAgent?.enabled !== false &&
    !preparedIntent &&
    preparingTransactionId === null;

  const handlePrepareTransaction = async () => {
    if (
      !selectedTransaction ||
      !transactionAgent?.authorizedNearAccountId ||
      !canPrepareSavedTransaction(selectedTransaction, transactionApprovalStatus) ||
      transactionAgent.enabled === false ||
      preparedIntents[selectedTransaction.id] ||
      preparationInProgressRef.current
    ) {
      return;
    }

    preparationInProgressRef.current = true;
    clearAuthorizationToken("intent-replaced");
    setRevocationNotice(null);
    const tokenGeneration = authorizationTokenGenerationRef.current;
    const accountAtPreparation = accountIdRef.current;
    const selectedAgentAtPreparation = selectedAgentIdRef.current;
    setPreparingTransactionId(selectedTransaction.id);
    setPreparationError(null);
    try {
      const preparedResponse = await prepareSavedTransaction(selectedTransaction.id);
      const {
        authorizationToken,
        ...prepared
      }: PreparedAuthorizationResponse = preparedResponse;
      if (
        prepared.recipient !== selectedTransaction.recipient ||
        prepared.amountYocto !== selectedTransaction.amountYocto ||
        prepared.policyVersion !== selectedTransaction.decision.policyVersion ||
        prepared.expectedSignerAccountId !== transactionAgent.authorizedNearAccountId ||
        (selectedTransaction.decision.decision === "WARN" && prepared.approval === null) ||
        (selectedTransaction.decision.decision === "ALLOW" && prepared.approval !== null)
      ) {
        throw new Error(
          "The preparation response did not match the saved transaction and provisioned signer. The token was discarded; do not retry this transaction. Ask the local operator to inspect the audit record and re-evaluate it.",
        );
      }

      setPreparedIntents((current) => ({
        ...current,
        [selectedTransaction.id]: prepared,
      }));
      if (
        tokenGeneration === authorizationTokenGenerationRef.current &&
        selectedAgentAtPreparation === selectedAgentIdRef.current &&
        accountAtPreparation !== null &&
        accountAtPreparation === accountIdRef.current &&
        accountAtPreparation === prepared.expectedSignerAccountId
      ) {
        const replacedIntentId = storeTemporaryAuthorizationToken(
          authorizationTokenRef,
          preparedResponse,
          selectedTransaction.id,
          selectedTransaction.agentId,
        );
        if (replacedIntentId) {
          setAuthorizationTokenStates((current) => ({
            ...current,
            [replacedIntentId]: "cleared",
          }));
        }
        setAuthorizationTokenStates((current) => ({
          ...current,
          [prepared.intentId]: "available",
        }));
        setActiveAuthorizationTokenIntentId(prepared.intentId);
      } else {
        setAuthorizationTokenStates((current) => ({
          ...current,
          [prepared.intentId]: "not-retained",
        }));
        void revokeAuthorizationIntent(prepared.intentId, authorizationToken)
          .then(() => {
            setAuthorizationTokenStates((current) => ({
              ...current,
              [prepared.intentId]: "revoked",
            }));
          })
          .catch(() => {
            setAuthorizationTokenStates((current) => ({
              ...current,
              [prepared.intentId]: "revocation-failed",
            }));
            setRevocationNotice(
              `SENTRA could not confirm revocation of intent ${prepared.intentId}. It may remain valid until ${new Date(prepared.expiresAt).toLocaleString()}. No automatic retry will be made.`,
            );
          });
      }
      setAuthorizationClock(Date.now());
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        typeof error.code === "string" &&
        ["AUTHORIZATION_REPLAY", "AUTHORIZATION_EXPIRED", "AUTHORIZATION_STALE", "STALE_AUTHORIZATION"]
          .includes(error.code)
      ) {
        clearAuthorizationToken("invalidated");
      }
      setPreparationError(
        error instanceof Error ? error.message : "SENTRA could not prepare this transaction.",
      );
    } finally {
      preparationInProgressRef.current = false;
      setPreparingTransactionId(null);
    }
  };

  const refreshSavedTransactions = async (
    isActive: () => boolean = () => true,
  ): Promise<void> => {
    const requestSequence = ++transactionsRefreshSequenceRef.current;
    try {
      const reviewData = await loadTransactionReviewData();
      if (!isActive() || requestSequence !== transactionsRefreshSequenceRef.current) return;
      setTransactions(reviewData.transactions);
      setApprovals(reviewData.approvals);
      setSelectedTransactionId((current) =>
        current && reviewData.transactions.some((transaction) => transaction.id === current)
          ? current
          : "",
      );
      setTransactionsError(null);
    } catch {
      if (!isActive() || requestSequence !== transactionsRefreshSequenceRef.current) return;
      setTransactionsError("Could not load saved transactions and approval records from SENTRA.");
      throw new Error("Transaction evaluation was saved, but the saved transaction list could not be refreshed.");
    } finally {
      if (isActive() && requestSequence === transactionsRefreshSequenceRef.current) {
        setTransactionsLoading(false);
      }
    }
  };

  const handleApprovalReview = async (
    approval: SavedApproval,
    transaction: SavedTransaction,
    action: ApprovalReviewAction,
  ) => {
    if (approvalActionBusyId !== null) return;
    setApprovalActionBusyId(approval.id);
    setApprovalFeedback(null);
    try {
      await reviewWarnApproval(
        approval,
        transaction,
        action,
        rejectionReasons[approval.id] ?? "",
      );
      const actionLabel = action === "approve" ? "approved" : "rejected";
      setRejectionReasons((current) => ({ ...current, [approval.id]: "" }));
      try {
        await refreshSavedTransactions();
        setApprovalFeedback({
          approvalId: approval.id,
          kind: "success",
          message: `WARN approval ${actionLabel}. Reviewer identity is unverified in this local demo.`,
        });
      } catch {
        setApprovalFeedback({
          approvalId: approval.id,
          kind: "error",
          message: `WARN approval was ${actionLabel}, but SENTRA could not refresh the approval and transaction lists.`,
        });
      }
    } catch (error) {
      setApprovalFeedback({
        approvalId: approval.id,
        kind: "error",
        message: error instanceof Error ? error.message : "SENTRA could not update this approval.",
      });
    } finally {
      setApprovalActionBusyId(null);
    }
  };

  const handleThreatSimulation = async () => {
    if (!threatLabAgent || !selectedThreatScenario || threatLabBusy) return;
    setThreatLabBusy(true);
    setThreatLabError(null);
    setThreatLabResult(null);
    try {
      const result = await runThreatSimulation(
        threatLabAgent.id,
        selectedThreatScenario.id,
      );
      setThreatLabResult(result);
    } catch (error) {
      setThreatLabError(
        error instanceof Error ? error.message : "SENTRA could not run this simulation.",
      );
    } finally {
      setThreatLabBusy(false);
    }
  };

  const handlePublicDemoSimulation = async () => {
    if (!publicDemoScenarioId || publicDemoBusy) return;
    setPublicDemoBusy(true);
    setPublicDemoError(null);
    setPublicDemoResult(null);
    try {
      setPublicDemoResult(await runPublicThreatSimulation(
        publicDemoScenarioId,
      ));
    } catch (error) {
      setPublicDemoError(
        error instanceof Error ? error.message : "SENTRA could not run the public demo.",
      );
    } finally {
      setPublicDemoBusy(false);
    }
  };

  const handleEvaluateTransaction = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!composerAgent || composerAgent.enabled !== true || evaluationInProgressRef.current) {
      setEvaluationError("Select an enabled registered agent.");
      return;
    }

    evaluationInProgressRef.current = true;
    clearAuthorizationToken("intent-replaced");
    setEvaluationBusy(true);
    setEvaluationError(null);
    setEvaluationResult(null);
    try {
      const result = await submitTransactionEvaluation({
        agentId: composerAgent.id,
        recipient: composerRecipient,
        amountNear: composerAmount,
      });
      setEvaluationResult(result);
      try {
        await refreshSavedTransactions();
      } catch (error) {
        setEvaluationError(
          error instanceof Error
            ? error.message
            : "Evaluation completed, but saved transactions could not be refreshed.",
        );
      }
      clearAuthorizationToken("intent-replaced");
      selectedTransactionIdRef.current = result.transactionId;
      setSelectedTransactionId(result.transactionId);
    } catch (error) {
      setEvaluationError(
        error instanceof Error ? error.message : "SENTRA could not evaluate this transaction.",
      );
    } finally {
      evaluationInProgressRef.current = false;
      setEvaluationBusy(false);
    }
  };

  const selectAgent = (agentId: string) => {
    if (selectedAgentIdRef.current !== agentId) {
      clearAuthorizationToken("agent-changed");
      selectedAgentIdRef.current = agentId;
    }
    setSelectedAgentId(agentId);
  };

  useEffect(() => {
    if (selectedAgentIdRef.current === selectedAgentId) return;
    clearAuthorizationToken("agent-changed");
    selectedAgentIdRef.current = selectedAgentId;
  }, [selectedAgentId]);

  useEffect(() => {
    if (selectedTransactionIdRef.current === selectedTransactionId) return;
    clearAuthorizationToken("intent-replaced");
    selectedTransactionIdRef.current = selectedTransactionId;
  }, [selectedTransactionId]);

  useEffect(() => {
    if (!isAuthenticated) return;
    let active = true;
    let requestInProgress = false;

    const loadAgents = async () => {
      if (requestInProgress) return;
      requestInProgress = true;
      try {
        const response = await authenticatedApiFetch("/api/agents", {
          method: "GET",
          headers: { accept: "application/json" },
          cache: "no-store",
        });
        if (!response.ok) {
          throw new Error(`Agent API returned HTTP ${response.status}.`);
        }
        const records = parseAgentsResponse(await response.json());
        if (!active) return;
        const currentToken = authorizationTokenRef.current;
        if (currentToken) {
          const currentAgent = records.find((agent) => agent.id === currentToken.agentId);
          if (
            !currentAgent ||
            currentAgent.enabled !== true ||
            currentAgent.authorizedNearAccountId !== currentToken.expectedSignerAccountId
          ) {
            clearAuthorizationToken("invalidated");
          }
        }
        setAgents(records);
        setSelectedAgentId((current) =>
          current && records.some((agent) => agent.id === current)
            ? current
            : "",
        );
        setComposerAgentId((current) =>
          current && records.some((agent) => agent.id === current && agent.enabled === true)
            ? current
            : records.find((agent) => agent.enabled === true)?.id ?? "",
        );
        setThreatLabAgentId((current) =>
          current && records.some((agent) => agent.id === current)
            ? current
            : records[0]?.id ?? "",
        );
        setAgentsError(null);
      } catch {
        if (active) {
          setAgentsError("Could not load registered agents from the local SENTRA API.");
        }
      } finally {
        requestInProgress = false;
        if (active) setAgentsLoading(false);
      }
    };

    void loadAgents();
    const intervalId = window.setInterval(() => {
      void loadAgents();
    }, 5000);
    window.addEventListener("focus", loadAgents);
    return () => {
      active = false;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", loadAgents);
    };
  }, [isAuthenticated]);

  useEffect(() => {
    let active = true;
    void loadThreatScenarios()
      .then((scenarios) => {
        if (!active) return;
        setThreatLabScenarios(scenarios);
        setThreatLabScenarioId((current) =>
          current && scenarios.some((scenario) => scenario.id === current)
            ? current
            : scenarios[0]?.id ?? "",
        );
        setPublicDemoScenarioId((current) =>
          current && scenarios.some((scenario) => scenario.id === current)
            ? current
            : scenarios[0]?.id ?? "",
        );
        setThreatLabError(null);
      })
      .catch((error: unknown) => {
        if (!active) return;
        setThreatLabError(
          error instanceof Error ? error.message : "Could not load Threat Lab scenarios.",
        );
      })
      .finally(() => {
        if (active) setThreatLabScenariosLoading(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (!isAuthenticated) return;
    if (!activeAuthorizationTokenIntentId) return;
    const activeToken = authorizationTokenRef.current;
    if (!activeToken || activeToken.intentId !== activeAuthorizationTokenIntentId) return;

    let active = true;
    let requestInProgress = false;
    const checkCurrentPolicy = async () => {
      if (requestInProgress) return;
      requestInProgress = true;
      try {
        const response = await authenticatedApiFetch(
          `/api/agents/${encodeURIComponent(activeToken.agentId)}/policy`,
          {
            headers: { accept: "application/json" },
            cache: "no-store",
          },
        );
        if (!response.ok) {
          if (active) clearAuthorizationToken("invalidated");
          return;
        }
        const payload: unknown = await response.json();
        if (
          active &&
          authorizationTokenRef.current?.intentId === activeToken.intentId &&
          typeof payload === "object" &&
          payload !== null &&
          "data" in payload &&
          typeof payload.data === "object" &&
          payload.data !== null &&
          (!("version" in payload.data) ||
            typeof payload.data.version !== "string" ||
            payload.data.version !== preparedIntents[activeToken.transactionId]?.policyVersion)
        ) {
          clearAuthorizationToken("invalidated");
        } else if (
          active &&
          authorizationTokenRef.current?.intentId === activeToken.intentId &&
          (typeof payload !== "object" ||
            payload === null ||
            !("data" in payload) ||
            typeof payload.data !== "object" ||
            payload.data === null)
        ) {
          clearAuthorizationToken("invalidated");
        }
      } catch {
        if (active) clearAuthorizationToken("invalidated");
      } finally {
        requestInProgress = false;
      }
    };

    const clearOnPageHide = () => clearAuthorizationToken("session-ended");
    void checkCurrentPolicy();
    const intervalId = window.setInterval(() => void checkCurrentPolicy(), 5000);
    window.addEventListener("focus", checkCurrentPolicy);
    window.addEventListener("pagehide", clearOnPageHide);
    return () => {
      active = false;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", checkCurrentPolicy);
      window.removeEventListener("pagehide", clearOnPageHide);
    };
  }, [activeAuthorizationTokenIntentId, isAuthenticated, preparedIntents]);

  useEffect(() => {
    if (!isAuthenticated) return;
    let active = true;
    let requestInProgress = false;

    const loadTransactions = async () => {
      if (requestInProgress) return;
      requestInProgress = true;
      try {
        await refreshSavedTransactions(() => active);
      } catch {
        // The shared refresh helper records the visible error state.
      } finally {
        requestInProgress = false;
      }
    };

    void loadTransactions();
    const intervalId = window.setInterval(() => {
      void loadTransactions();
    }, 5000);
    window.addEventListener("focus", loadTransactions);
    return () => {
      active = false;
      window.clearInterval(intervalId);
      window.removeEventListener("focus", loadTransactions);
    };
  }, []);

  useEffect(() => {
    if (!activeAuthorizationTokenIntentId) return;

    const checkExpiry = () => {
      setAuthorizationClock(Date.now());
      expireAuthorizationToken();
    };
    const expiresAt = authorizationTokenRef.current?.expiresAt ?? Date.now();
    const timeoutId = window.setTimeout(
      checkExpiry,
      Math.max(0, expiresAt - Date.now()),
    );
    const intervalId = window.setInterval(checkExpiry, 1000);
    window.addEventListener("focus", checkExpiry);
    return () => {
      window.clearTimeout(timeoutId);
      window.clearInterval(intervalId);
      window.removeEventListener("focus", checkExpiry);
    };
  }, [activeAuthorizationTokenIntentId]);

  useEffect(() => {
    if (Object.keys(preparedIntents).length === 0) return;
    const intervalId = window.setInterval(() => setAuthorizationClock(Date.now()), 1000);
    return () => window.clearInterval(intervalId);
  }, [preparedIntents]);

  useEffect(() => () => {
    clearAuthorizationToken("session-ended");
  }, []);

  if (!isAuthenticated) {
    return (
      <main className="app-shell">
        <header className="brand">
          <div className="brand-mark" aria-hidden="true">
            <span />
          </div>
          <span className="brand-name">SENTRA</span>
          <span className="brand-divider" />
          <span className="brand-section">Operator access</span>
        </header>

        <section className="wallet-panel access-panel" aria-labelledby="access-title">
          <div className="panel-kicker">
            <span className="status-dot" />
            SECURE OPERATOR ACCESS
          </div>
          <h1 id="access-title">Access SENTRA</h1>
          <p className="panel-description">
            Enter the shared operator token to open the local SENTRA dashboard.
          </p>
          <form className="access-form" onSubmit={(event) => void handleAccessSubmit(event)}>
            <label className="agent-select-label" htmlFor="sentra-access-token">
              Access token
            </label>
            <input
              id="sentra-access-token"
              className="agent-select"
              type="password"
              autoComplete="current-password"
              value={accessTokenInput}
              onChange={(event) => setAccessTokenInput(event.target.value)}
              required
              disabled={accessBusy}
            />
            {accessError && <p className="auth-error" role="alert">{accessError}</p>}
            <button
              className="primary-button access-submit"
              type="submit"
              disabled={accessBusy || accessTokenInput.length === 0}
            >
              {accessBusy ? "Verifying..." : "Continue"}
            </button>
            <p className="privacy-note">
              The token is kept in memory only and is cleared when you log out or close this page.
            </p>
          </form>
        </section>

        <section className="authorization-section threat-lab-section" aria-labelledby="public-demo-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">PUBLIC THREAT LAB</span>
              <h2 id="public-demo-title">Public Synthetic Demo</h2>
            </div>
            <span className="simulation-label">NO LOGIN REQUIRED</span>
          </div>
          <p className="authorization-intro">
            Explore fixed synthetic scenarios evaluated with SENTRA&apos;s deterministic policy
            engine. This demo uses no registered agents or saved policies and does not create
            records, authorize wallets, or execute transactions.
          </p>
          <div className="threat-lab-controls">
            <label className="agent-select-label" htmlFor="public-demo-scenario">
              Attack scenario
            </label>
            <select
              id="public-demo-scenario"
              className="agent-select"
              value={publicDemoScenarioId}
              onChange={(event) => {
                setPublicDemoScenarioId(event.target.value);
                setPublicDemoResult(null);
                setPublicDemoError(null);
              }}
              disabled={threatLabScenariosLoading || threatLabScenarios.length === 0 || publicDemoBusy}
            >
              <option value="">
                {threatLabScenariosLoading ? "Loading scenarios…" : "Select an attack scenario"}
              </option>
              {threatLabScenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>{scenario.name}</option>
              ))}
            </select>
            {threatLabError && <p className="error-message" role="alert">{threatLabError}</p>}
            {publicDemoError && <p className="error-message" role="alert">{publicDemoError}</p>}
            {!threatLabError && !threatLabScenariosLoading && threatLabScenarios.length === 0 && (
              <p className="binding-help" role="status">No public demo scenarios are available.</p>
            )}
            <button
              className="primary-button evaluate-transaction-button"
              type="button"
              onClick={() => void handlePublicDemoSimulation()}
              disabled={
                publicDemoBusy ||
                !publicDemoScenarioId ||
                threatLabScenariosLoading
              }
            >
              {publicDemoBusy ? "Running synthetic demo…" : "Run Public Demo"}
            </button>
          </div>
          {publicDemoResult && (
            <article
              className={`threat-simulation-result ${
                publicDemoResult.decision === "BLOCK" ? "threat-result-blocked" : ""
              }`}
              role="status"
              aria-live="polite"
            >
              <div className="transaction-review-heading">
                <span className={`decision-badge decision-${publicDemoResult.decision.toLowerCase()}`}>
                  {publicDemoResult.decision}
                </span>
                <span className="simulation-label">PUBLIC · SYNTHETIC</span>
              </div>
              <div className="transaction-review-row">
                <span className="field-label">Simulated malicious action</span>
                <span className="transaction-value">{publicDemoResult.simulatedResponse}</span>
              </div>
              <div className="transaction-review-row">
                <span className="field-label">Synthetic proposal</span>
                <span className="transaction-value">
                  {publicDemoResult.proposedTransaction.recipient} ·{" "}
                  {formatYoctoNear(publicDemoResult.proposedTransaction.amountYocto) ??
                    publicDemoResult.proposedTransaction.amountYocto} NEAR
                </span>
              </div>
              <div className="transaction-reasons">
                <span className="field-label">Triggered policy rules</span>
                {publicDemoResult.triggeredRules.length > 0 ? (
                  <ul>
                    {publicDemoResult.triggeredRules.map((rule) => (
                      <li key={rule}><strong>{rule}</strong></li>
                    ))}
                  </ul>
                ) : (
                  <span className="transaction-value">No specific rule was triggered.</span>
                )}
              </div>
              <p className="threat-simulation-explanation">{publicDemoResult.explanation}</p>
              <p className="binding-help">
                Synthetic only. No real agent, policy, transaction, approval, wallet binding,
                authorization intent, or audit record was accessed or changed.
              </p>
            </article>
          )}
        </section>
      </main>
    );
  }

  return (
    <main className="app-shell">
      <header className="brand">
        <div className="brand-mark" aria-hidden="true">
          <span />
        </div>
        <span className="brand-name">SENTRA</span>
        <span className="brand-divider" />
        <span className="brand-section">Wallet connection</span>
        <button className="secondary-button logout-button" type="button" onClick={handleLogout}>
          Log out
        </button>
      </header>

      <section className="wallet-panel" aria-labelledby="wallet-title">
        <div className="panel-kicker">
          <span className="status-dot" data-connected={connected} />
          LOCAL TESTNET SESSION
        </div>
        <h1 id="wallet-title">Connect a NEAR wallet</h1>
        <p className="panel-description">
          Connect to view the account selected in your wallet. SENTRA will not request a message
          signature or wallet credentials.
        </p>

        <div className="connection-card" aria-live="polite">
          <div className="connection-row">
            <span className="field-label">Connection</span>
            <span className={`connection-status ${connected ? "is-connected" : ""}`}>
              {status === "connecting" && "Connecting"}
              {status === "disconnecting" && "Disconnecting"}
              {status === "connected" && "Connected"}
              {status === "disconnected" && "Not connected"}
              {status === "error" && "Needs attention"}
            </span>
          </div>
          <div className="connection-row account-row">
            <span className="field-label">NEAR account ID</span>
            <span className="account-value">
              {accountId ?? "—"}
            </span>
          </div>
          <div className="connection-row">
            <span className="field-label">Testnet account check</span>
            <span className="network-value">
              <span
                className={`verification-chip verification-${accountCheckStatus}`}
                data-status={accountCheckStatus}
              >
                {accountCheckStatus === "checking" && "CHECKING"}
                {accountCheckStatus === "verified" && "ACCOUNT FOUND"}
                {accountCheckStatus === "missing" && "NOT FOUND"}
                {accountCheckStatus === "unverified" && "UNVERIFIED"}
                {accountCheckStatus === "stale" && "ACCOUNT CHANGED"}
                {accountCheckStatus === "invalid" && "INVALID"}
                {accountCheckStatus === "idle" && "NOT CHECKED"}
              </span>
              <span>
                {accountCheckStatus === "verified" && "Exists on Testnet"}
                {accountCheckStatus === "missing" && "Not found on Testnet"}
                {(accountCheckStatus === "unverified" || accountCheckStatus === "stale") &&
                  "Unverified"}
                {(accountCheckStatus === "checking" || accountCheckStatus === "idle" ||
                  accountCheckStatus === "invalid") && "—"}
              </span>
            </span>
          </div>
          <div className="connection-row">
            <span className="field-label">Active wallet network</span>
            <span className="network-value">
              <span className="network-chip">UNVERIFIED</span>
              <span>Connector exposes no trusted active-network identity</span>
            </span>
          </div>
        </div>

        <section className="binding-section" aria-labelledby="binding-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">AGENT REGISTRY</span>
              <h2 id="binding-title">Agent Registry</h2>
            </div>
            <span className={`binding-badge binding-${bindingStatus.toLowerCase().replaceAll(" ", "-")}`}>
              {bindingStatus}
            </span>
          </div>
          <button
            className="secondary-button register-agent-button"
            type="button"
            onClick={() => {
              setRegistrationOpen((open) => !open);
              setRegistrationError(null);
              setRegistrationMessage(null);
            }}
          >
            {registrationOpen ? "Close form" : "Register Agent"}
          </button>
          {registrationOpen && (
            <form className="agent-registration-form" onSubmit={(event) => void handleRegisterAgent(event)}>
              <label className="agent-select-label" htmlFor="agent-name">
                Agent name
              </label>
              <input
                id="agent-name"
                className="agent-select"
                type="text"
                value={registrationName}
                onChange={(event) => setRegistrationName(event.target.value)}
                maxLength={120}
                required
                autoComplete="off"
                disabled={registrationBusy}
              />
              <label className="agent-select-label description-label" htmlFor="agent-description">
                Description <span>(optional)</span>
              </label>
              <textarea
                id="agent-description"
                className="agent-description"
                value={registrationDescription}
                onChange={(event) => setRegistrationDescription(event.target.value)}
                maxLength={2000}
                rows={3}
                disabled={registrationBusy}
              />
              {registrationError && (
                <p className="error-message" role="alert">{registrationError}</p>
              )}
              <button
                className="primary-button register-submit"
                type="submit"
                disabled={registrationBusy || registrationName.trim().length === 0}
              >
                {registrationBusy ? "Registering…" : "Create Agent"}
              </button>
            </form>
          )}
          {registrationMessage && (
            <p className="registration-success" role="status">{registrationMessage}</p>
          )}
          <label className="agent-select-label" htmlFor="agent-select">
            Registered agent
          </label>
          <select
            id="agent-select"
            className="agent-select"
            value={selectedAgentId}
            onChange={(event) => selectAgent(event.target.value)}
            disabled={agentsLoading || agents.length === 0}
          >
            <option value="">
              {agentsLoading ? "Loading agents…" : "Select an agent"}
            </option>
            {agents.map((agent) => (
              <option key={agent.id} value={agent.id}>
                {agent.name} · {agent.id}
              </option>
            ))}
          </select>

          <div className="binding-record">
            <span className="field-label">Provisioned wallet account</span>
            <span className="account-value">
              {selectedAgent
                ? selectedAgent.authorizedNearAccountId ?? "Not bound"
                : "Select an agent"}
            </span>
          </div>
          {agentsError && <p className="error-message" role="alert">{agentsError}</p>}
          {!agentsError && !agentsLoading && agents.length === 0 && (
            <p className="binding-help" role="status">No registered agents are available.</p>
          )}
          {selectedAgent && selectedAgent.authorizedNearAccountId === null && (
            <p className="binding-help">
              Wallet bindings can only be created or changed by an operator using the backend's
              local provisioning CLI. SENTRA will not modify this binding from the frontend.
            </p>
          )}
          {bindingStatus === "MISMATCH" && (
            <p className="binding-warning" role="status">
              The connected account does not match this agent's provisioned wallet. No binding
              was changed.
            </p>
          )}
          {bindingStatus === "MATCH" && (
            <p className="binding-match" role="status">
              The connected account matches the saved binding. This is a local identity comparison,
              not proof of the wallet's active network.
            </p>
          )}
        </section>

        <section className="authorization-section composer-section" aria-labelledby="composer-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">DETERMINISTIC POLICY ENGINE</span>
              <h2 id="composer-title">New Transaction</h2>
            </div>
          </div>
          <p className="authorization-intro">
            Create a saved proposal for deterministic evaluation. This form supports only a
            native NEAR transfer on Testnet. Evaluation does not approve WARN decisions or prepare
            a transaction for signing.
          </p>

          <form className="transaction-composer-form" onSubmit={(event) => void handleEvaluateTransaction(event)}>
            <label className="agent-select-label" htmlFor="composer-agent-select">
              Enabled agent
            </label>
            <select
              id="composer-agent-select"
              className="agent-select"
              value={composerAgentId}
              onChange={(event) => {
                clearAuthorizationToken("agent-changed");
                setComposerAgentId(event.target.value);
              }}
              disabled={agentsLoading || enabledAgents.length === 0 || evaluationBusy}
              required
            >
              <option value="">
                {agentsLoading ? "Loading agents…" : "Select an enabled agent"}
              </option>
              {enabledAgents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name} · {agent.id}
                </option>
              ))}
            </select>

            <label className="agent-select-label" htmlFor="composer-recipient">
              Recipient NEAR account ID
            </label>
            <input
              id="composer-recipient"
              className="agent-select"
              type="text"
              value={composerRecipient}
              onChange={(event) => setComposerRecipient(event.target.value)}
              minLength={2}
              maxLength={64}
              autoComplete="off"
              spellCheck={false}
              required
              disabled={evaluationBusy}
              placeholder="recipient.testnet"
            />

            <label className="agent-select-label" htmlFor="composer-amount">
              Amount in NEAR
            </label>
            <input
              id="composer-amount"
              className="agent-select"
              type="text"
              inputMode="decimal"
              value={composerAmount}
              onChange={(event) => setComposerAmount(event.target.value)}
              autoComplete="off"
              required
              disabled={evaluationBusy}
              placeholder="0.5"
              aria-describedby="composer-amount-help"
            />
            <p id="composer-amount-help" className="composer-help">
              Positive decimal amount; up to 24 decimal places. Scientific notation is not accepted.
            </p>

            <div className="transaction-fixed-fields" aria-label="Fixed transaction network and type">
              <span><strong>Network</strong> NEAR Testnet</span>
              <span><strong>Asset</strong> Native NEAR</span>
              <span><strong>Type</strong> Transfer</span>
            </div>

            {evaluationError && (
              <p className="error-message" role="alert">{evaluationError}</p>
            )}
            <button
              className="primary-button evaluate-transaction-button"
              type="submit"
              disabled={evaluationBusy || !composerAgent || composerAgent.enabled !== true}
            >
              {evaluationBusy ? "Evaluating policy…" : "Evaluate Transaction"}
            </button>
          </form>

          {evaluationResult && (
            <div className="evaluation-result-card" role="status" aria-live="polite">
              <div className="transaction-review-heading">
                <span className={`decision-badge decision-${evaluationResult.decision.toLowerCase()}`}>
                  {evaluationResult.decision}
                </span>
                <span className="transaction-id">{evaluationResult.transactionId}</span>
              </div>
              <p className="evaluation-result-title">
                {evaluationResult.decision === "ALLOW" && "Policy evaluation allowed this proposal."}
                {evaluationResult.decision === "WARN" && "Human approval is required before preparation."}
                {evaluationResult.decision === "BLOCK" && "Policy blocked this proposal."}
              </p>
              <div className="transaction-review-row">
                <span className="field-label">Policy version</span>
                <span className="transaction-value mono-value">
                  {evaluationResult.policyVersion ?? "Unavailable"}
                </span>
              </div>
              <div className="transaction-reasons">
                <span className="field-label">Deterministic rules and explanations</span>
                <ul>
                  {evaluationResult.triggeredRules.map((rule, index) => (
                    <li key={`${evaluationResult.decisionId}-${rule}-${index}`}>
                      <strong>{rule}</strong>
                      {evaluationResult.reasons[index] ? ` — ${evaluationResult.reasons[index]}` : ""}
                    </li>
                  ))}
                </ul>
              </div>
              {evaluationResult.decision === "WARN" && (
                <div className="approval-review">
                  <span className="approval-state approval-pending">
                    Approval status: {evaluationResult.approval?.status ?? "missing"}
                  </span>
                  <p>
                    SENTRA created a pending approval record. No approval was granted by this
                    interface. A reviewer must use the existing approval workflow; reviewer
                    identity is not authenticated by this local development API.
                  </p>
                </div>
              )}
              {evaluationResult.decision === "BLOCK" && (
                <p className="authorization-blocked">
                  This saved BLOCK decision cannot be prepared. No override or approval is offered here.
                </p>
              )}
              <p className="binding-help">
                Saved for review; not prepared, signed, broadcast, executed or verified.
              </p>
            </div>
          )}
        </section>

        <section className="authorization-section threat-lab-section" aria-labelledby="threat-lab-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">THREAT LAB</span>
              <h2 id="threat-lab-title">Instruction attack simulations</h2>
            </div>
            <span className="simulation-label">DETERMINISTIC SIMULATION</span>
          </div>
          <p className="authorization-intro">
            Run a synthetic attack proposal through SENTRA's saved deterministic policy. These
            scenarios do not invoke or attack a real AI agent or LLM, and no transaction is executed.
          </p>

          <div className="threat-lab-controls">
            <label className="agent-select-label" htmlFor="threat-lab-agent">
              Registered agent
            </label>
            <select
              id="threat-lab-agent"
              className="agent-select"
              value={threatLabAgentId}
              onChange={(event) => {
                setThreatLabAgentId(event.target.value);
                setThreatLabResult(null);
                setThreatLabError(null);
              }}
              disabled={agentsLoading || agents.length === 0 || threatLabBusy}
            >
              <option value="">
                {agentsLoading ? "Loading agents…" : "Select a registered agent"}
              </option>
              {agents.map((agent) => (
                <option key={agent.id} value={agent.id}>
                  {agent.name} · {agent.enabled ? "enabled" : "disabled"}
                </option>
              ))}
            </select>

            <label className="agent-select-label" htmlFor="threat-lab-scenario">
              Attack scenario
            </label>
            <select
              id="threat-lab-scenario"
              className="agent-select"
              value={threatLabScenarioId}
              onChange={(event) => {
                setThreatLabScenarioId(event.target.value);
                setThreatLabResult(null);
                setThreatLabError(null);
              }}
              disabled={threatLabScenariosLoading || threatLabScenarios.length === 0 || threatLabBusy}
            >
              <option value="">
                {threatLabScenariosLoading ? "Loading scenarios…" : "Select an attack scenario"}
              </option>
              {threatLabScenarios.map((scenario) => (
                <option key={scenario.id} value={scenario.id}>{scenario.name}</option>
              ))}
            </select>

            {threatLabError && <p className="error-message" role="alert">{threatLabError}</p>}
            {!threatLabError && threatLabScenarios.length === 0 && !threatLabScenariosLoading && (
              <p className="binding-help" role="status">No Threat Lab scenarios were returned.</p>
            )}
            {selectedThreatScenario && (
              <div className="threat-scenario-preview">
                <p>{selectedThreatScenario.description}</p>
                <span className="field-label">Synthetic malicious instruction</span>
                <blockquote>{selectedThreatScenario.maliciousInstruction}</blockquote>
              </div>
            )}
            <button
              className="primary-button evaluate-transaction-button"
              type="button"
              onClick={() => void handleThreatSimulation()}
              disabled={
                threatLabBusy ||
                !threatLabAgent ||
                !selectedThreatScenario ||
                threatLabScenariosLoading
              }
            >
              {threatLabBusy ? "Running simulation…" : "Run Simulation"}
            </button>
          </div>

          {threatLabResult && (
            <article
              className={`threat-simulation-result ${
                threatLabResult.simulation.decision === "BLOCK" ? "threat-result-blocked" : ""
              }`}
              role="status"
              aria-live="polite"
            >
              <div className="transaction-review-heading">
                <span
                  className={`decision-badge decision-${threatLabResult.simulation.decision.toLowerCase()}`}
                >
                  {threatLabResult.simulation.decision}
                </span>
                <span className="transaction-id">{threatLabResult.simulation.id}</span>
              </div>
              <p className="simulation-label">DETERMINISTIC SIMULATION · NOT A REAL AGENT OR LLM</p>
              <div className="transaction-review-row">
                <span className="field-label">Simulated malicious action</span>
                <span className="transaction-value">{threatLabResult.simulation.simulatedResponse}</span>
              </div>
              <div className="transaction-review-row">
                <span className="field-label">Proposed transfer</span>
                <span className="transaction-value">
                  {threatLabResult.simulation.proposedTransaction.recipient} ·{" "}
                  {formatYoctoNear(threatLabResult.simulation.proposedTransaction.amountYocto) ??
                    threatLabResult.simulation.proposedTransaction.amountYocto}{" "}
                  {threatLabResult.simulation.proposedTransaction.asset}
                </span>
              </div>
              <div className="transaction-review-row">
                <span className="field-label">Policy result</span>
                <span className={`decision-badge decision-${threatLabResult.simulation.decision.toLowerCase()}`}>
                  {threatLabResult.simulation.decision} · {threatLabResult.simulation.outcome}
                </span>
              </div>
              <div className="transaction-review-row">
                <span className="field-label">Policy version</span>
                <span className="transaction-value mono-value">
                  {threatLabResult.simulation.policyVersion}
                </span>
              </div>
              <div className="transaction-reasons">
                <span className="field-label">Triggered policy rules</span>
                {threatLabResult.simulation.triggeredPolicyRules.length > 0 ? (
                  <ul>
                    {threatLabResult.simulation.triggeredPolicyRules.map((rule) => (
                      <li key={rule}><strong>{rule}</strong></li>
                    ))}
                  </ul>
                ) : (
                  <span className="transaction-value">No specific rule was triggered.</span>
                )}
              </div>
              <p className="threat-simulation-explanation">
                {threatLabResult.simulation.explanation}
              </p>
              {threatLabResult.simulation.decision === "BLOCK" && (
                <p className="authorization-blocked threat-block-message">
                  BLOCK enforced. This simulated proposal cannot be approved or prepared.
                </p>
              )}
              <div className="threat-audit-info">
                <span className="field-label">Audit information</span>
                {threatLabResult.auditEvent ? (
                  <>
                    <span className="transaction-value">
                      {threatLabResult.auditEvent.eventType} ·{" "}
                      {new Date(threatLabResult.auditEvent.createdAt).toLocaleString()}
                    </span>
                    <span className="transaction-id">Audit event {threatLabResult.auditEvent.id}</span>
                  </>
                ) : (
                  <span className="transaction-value">
                    Simulation saved as {threatLabResult.simulation.id} at{" "}
                    {new Date(threatLabResult.simulation.createdAt).toLocaleString()}; the audit
                    event was not returned by the audit API.
                  </span>
                )}
              </div>
              <p className="binding-help">
                Simulated only. No transaction was prepared, signed, broadcast, or executed.
              </p>
            </article>
          )}
        </section>

        <section className="authorization-section approval-center" aria-labelledby="approval-center-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">HUMAN APPROVAL CENTER</span>
              <h2 id="approval-center-title">Pending WARN approvals</h2>
            </div>
            <span className="approval-state approval-pending">
              {pendingWarnApprovals.length} pending
            </span>
          </div>
          <p className="authorization-intro">
            Review only pending WARN decisions linked to their saved transaction and policy
            snapshot. Approval records a local review decision; it does not sign, broadcast, or
            execute a transaction.
          </p>
          <p className="approval-reviewer-notice">
            Reviewer identity is <strong>unverified</strong>. This is a local-demo approval, not
            authenticated human authorization.
          </p>
          {approvalFeedback && (
            <p
              className={approvalFeedback.kind === "success" ? "registration-success" : "error-message"}
              role={approvalFeedback.kind === "success" ? "status" : "alert"}
            >
              {approvalFeedback.message}
            </p>
          )}
          {transactionsLoading && (
            <p className="binding-help" role="status">Loading pending approvals…</p>
          )}
          {!transactionsLoading && transactionsError && (
            <p className="error-message" role="alert">{transactionsError}</p>
          )}
          {!transactionsLoading && !transactionsError && pendingWarnApprovals.length === 0 && (
            <p className="binding-help" role="status">There are no pending WARN approvals.</p>
          )}

          <div className="pending-approvals-list">
            {pendingWarnApprovals.map(({ approval, transaction }) => {
              const agentName =
                agents.find((agent) => agent.id === transaction.agentId)?.name ??
                transaction.agentId;
              const amountNear = formatYoctoNear(transaction.amountYocto);
              const isBusy = approvalActionBusyId === approval.id;
              return (
                <article className="pending-approval-card" key={approval.id}>
                  <div className="transaction-review-heading">
                    <span className="decision-badge decision-warn">WARN</span>
                    <span className="transaction-id">{approval.id}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Agent</span>
                    <span className="transaction-value">{agentName}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Recipient</span>
                    <span className="transaction-value">{transaction.recipient}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Amount</span>
                    <span className="transaction-value">
                      {amountNear === null ? "Invalid amount" : `${amountNear} NEAR`}
                      <small>{transaction.amountYocto} yoctoNEAR</small>
                    </span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Policy decision</span>
                    <span className="transaction-value">
                      WARN · {transaction.decision.triggeredRules.join(", ")}
                    </span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Policy version</span>
                    <span className="transaction-value mono-value">{approval.policyVersion}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Approval created</span>
                    <span className="transaction-value">
                      {new Date(approval.createdAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="approval-actions">
                    <button
                      className="primary-button approval-action-button"
                      type="button"
                      onClick={() => void handleApprovalReview(approval, transaction, "approve")}
                      disabled={approvalActionBusyId !== null}
                    >
                      {isBusy ? "Saving review…" : "Approve WARN"}
                    </button>
                    <label className="agent-select-label" htmlFor={`reject-reason-${approval.id}`}>
                      Rejection reason
                    </label>
                    <textarea
                      id={`reject-reason-${approval.id}`}
                      className="agent-description approval-rejection-reason"
                      value={rejectionReasons[approval.id] ?? ""}
                      onChange={(event) =>
                        setRejectionReasons((current) => ({
                          ...current,
                          [approval.id]: event.target.value,
                        }))
                      }
                      maxLength={2000}
                      rows={2}
                      placeholder="Explain why this WARN is rejected"
                      disabled={approvalActionBusyId !== null}
                    />
                    <button
                      className="secondary-button approval-action-button"
                      type="button"
                      onClick={() => void handleApprovalReview(approval, transaction, "reject")}
                      disabled={
                        approvalActionBusyId !== null ||
                        (rejectionReasons[approval.id] ?? "").trim().length === 0
                      }
                    >
                      Reject WARN
                    </button>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        <section className="authorization-section" aria-labelledby="authorization-title">
          <div className="binding-heading">
            <div>
              <span className="section-eyebrow">TRANSACTION FIREWALL</span>
              <h2 id="authorization-title">Transaction authorization review</h2>
            </div>
          </div>
          <p className="authorization-intro">
            Review an existing deterministic evaluation. Preparation accepts only its saved
            transaction ID; SENTRA rechecks current policy and approval before issuing an intent.
          </p>

          <label className="agent-select-label" htmlFor="saved-transaction-select">
            Saved transaction
          </label>
          <select
            id="saved-transaction-select"
            className="agent-select"
            value={selectedTransactionId}
            onChange={(event) => {
              clearAuthorizationToken("intent-replaced");
              selectedTransactionIdRef.current = event.target.value;
              setSelectedTransactionId(event.target.value);
              setPreparationError(null);
            }}
            disabled={transactionsLoading || transactions.length === 0 || preparingTransactionId !== null}
          >
            <option value="">
              {transactionsLoading ? "Loading saved transactions…" : "Select a saved transaction"}
            </option>
            {transactions.map((transaction) => {
              const agentName =
                agents.find((agent) => agent.id === transaction.agentId)?.name ??
                transaction.agentId;
              const amountNear = formatYoctoNear(transaction.amountYocto);
              return (
                <option key={transaction.id} value={transaction.id}>
                  {agentName} · {transaction.decision.decision} ·{" "}
                  {amountNear === null ? transaction.amountYocto : `${amountNear} NEAR`} ·{" "}
                  {transaction.recipient}
                </option>
              );
            })}
          </select>

          {transactionsError && (
            <p className="error-message" role="alert">{transactionsError}</p>
          )}
          {!transactionsError && !transactionsLoading && transactions.length === 0 && (
            <p className="binding-help" role="status">
              No saved transactions are available. Evaluate a transaction through the existing
              SENTRA API before reviewing it here.
            </p>
          )}

          {selectedTransaction && (
            <>
              <div className="transaction-review-card">
                <div className="transaction-review-heading">
                  <span className={`decision-badge decision-${selectedTransaction.decision.decision.toLowerCase()}`}>
                    {selectedTransaction.decision.decision}
                  </span>
                  <span className="transaction-id">{selectedTransaction.id}</span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Agent</span>
                  <span className="transaction-value">
                    {transactionAgent?.name ?? "Unknown agent"} · {selectedTransaction.agentId}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Recipient</span>
                  <span className="transaction-value">{selectedTransaction.recipient}</span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Amount</span>
                  <span className="transaction-value">
                    {selectedTransactionAmount === null
                      ? "Invalid amount"
                      : `${selectedTransactionAmount} NEAR`}
                    <small>{selectedTransaction.amountYocto} yoctoNEAR</small>
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Network / asset</span>
                  <span className="transaction-value">
                    {selectedTransaction.network} · {selectedTransaction.asset}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Transaction type</span>
                  <span className="transaction-value">{selectedTransaction.transactionType}</span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Saved policy version</span>
                  <span className="transaction-value mono-value">
                    {selectedTransaction.decision.policyVersion}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Decision time</span>
                  <span className="transaction-value">
                    {new Date(selectedTransaction.decision.createdAt).toLocaleString()}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Provisioned signer</span>
                  <span className="transaction-value">
                    {transactionAgent?.authorizedNearAccountId ?? "Agent not found or wallet not bound"}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Connected account match</span>
                  <span className={`binding-badge binding-${getWalletBindingStatus(transactionAgent, accountId).toLowerCase().replaceAll(" ", "-")}`}>
                    {getWalletBindingStatus(transactionAgent, accountId)}
                  </span>
                </div>
                <div className="transaction-review-row">
                  <span className="field-label">Active wallet network</span>
                  <span className="network-chip">UNVERIFIED</span>
                </div>
                <div className="transaction-reasons">
                  <span className="field-label">Deterministic policy reasons</span>
                  {selectedTransaction.decision.reasons.length > 0 ? (
                    <ul>
                      {selectedTransaction.decision.reasons.map((reason, index) => (
                        <li key={`${selectedTransaction.decision.id}-${index}`}>{reason}</li>
                      ))}
                    </ul>
                  ) : (
                    <span className="transaction-value">No reason recorded</span>
                  )}
                </div>
                {selectedTransaction.decision.decision === "WARN" && (
                  <div className="approval-review">
                    <span className="field-label">Approval record</span>
                    <span className={`approval-state approval-${transactionApprovalStatus}`}>
                      {transactionApprovalStatus === "approved" && "Approved record linked"}
                      {transactionApprovalStatus === "pending" && "Pending"}
                      {transactionApprovalStatus === "rejected" && "Rejected"}
                      {transactionApprovalStatus === "missing" && "No matching approval"}
                    </span>
                    <p>
                      Approval is matched to this saved transaction, decision and policy snapshot.
                      Reviewer identity is not authenticated by this local development API; the
                      backend revalidates approval and policy during preparation.
                    </p>
                  </div>
                )}
              </div>

              {selectedTransaction.decision.decision === "BLOCK" && (
                <p className="authorization-blocked" role="status">
                  BLOCK is final for this saved evaluation. It cannot be prepared or authorized.
                  Re-evaluation creates a new saved decision; it does not override this BLOCK.
                </p>
              )}
              {selectedTransaction.decision.decision === "WARN" &&
                transactionApprovalStatus !== "approved" && (
                  <p className="binding-warning" role="status">
                    Preparation is unavailable until an approved record is linked to this exact
                    WARN decision and policy version.
                  </p>
                )}
              {transactionAgent?.authorizedNearAccountId === null && (
                <p className="binding-help" role="status">
                  This agent has no provisioned signer. Wallet binding remains a separate local
                  operator CLI action; connecting a wallet here does not create or change a binding.
                </p>
              )}
              {transactionAgent?.enabled === false && (
                <p className="authorization-blocked" role="status">
                  This agent is disabled. SENTRA will not prepare its transactions.
                </p>
              )}
              {!canPrepareSavedTransaction(selectedTransaction, transactionApprovalStatus) &&
                selectedTransaction.decision.decision !== "BLOCK" &&
                !(selectedTransaction.decision.decision === "WARN" &&
                  transactionApprovalStatus !== "approved") && (
                  <p className="binding-help" role="status">
                    Only saved native NEAR transfers on near-testnet can be prepared.
                  </p>
                )}

              <button
                className="primary-button prepare-transaction-button"
                type="button"
                onClick={() => void handlePrepareTransaction()}
                disabled={!transactionCanPrepare}
              >
                {preparingTransactionId === selectedTransaction.id
                  ? "Rechecking policy…"
                  : preparedIntent
                    ? "Already prepared"
                    : "Prepare authorization"}
              </button>
              {preparationError && (
                <p className="error-message" role="alert">{preparationError}</p>
              )}
              {revocationNotice && (
                <p className="error-message" role="alert">{revocationNotice}</p>
              )}

              {preparedIntent && (
                <div className="prepared-intent-card" role="status">
                  <div className="transaction-review-heading">
                    <span className={`decision-badge ${
                      preparedIntentExpired || authorizationTokenStates[preparedIntent.intentId] === "expired"
                        ? "decision-block"
                        : authorizationTokenStates[preparedIntent.intentId] === "available"
                          ? "decision-allow"
                          : "decision-warn"
                    }`}>
                      {preparedIntentExpired || authorizationTokenStates[preparedIntent.intentId] === "expired"
                        ? "EXPIRED"
                        : authorizationTokenStates[preparedIntent.intentId] === "available"
                          ? "PREPARED"
                          : authorizationTokenStates[preparedIntent.intentId] === "cleared"
                            ? "TOKEN CLEARED"
                            : authorizationTokenStates[preparedIntent.intentId] === "revoked"
                              ? "REVOKED"
                              : authorizationTokenStates[preparedIntent.intentId] === "revocation-failed"
                                ? "REVOCATION UNCONFIRMED"
                                : "PREPARED · TOKEN NOT RETAINED"}
                    </span>
                    <span className="transaction-id">{preparedIntent.intentId}</span>
                  </div>
                  <p>
                    {preparedIntentExpired
                      ? "This authorization intent has expired. It cannot be reused; re-evaluate the transaction before requesting a new decision."
                      : "Prepared only. This does not mean the transaction was signed, broadcast, executed or verified."}
                  </p>
                  <div className="transaction-review-row">
                    <span className="field-label">Expires</span>
                    <span className="transaction-value">
                      {new Date(preparedIntent.expiresAt).toLocaleString()}
                    </span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Expected signer</span>
                    <span className="transaction-value">{preparedIntent.expectedSignerAccountId}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Expected recipient</span>
                    <span className="transaction-value">{preparedIntent.recipient}</span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Expected amount</span>
                    <span className="transaction-value">
                      {preparedIntentAmount === null
                        ? "Invalid amount"
                        : `${preparedIntentAmount} NEAR`}
                      <small>{preparedIntent.amountYocto} yoctoNEAR</small>
                    </span>
                  </div>
                  <div className="transaction-review-row">
                    <span className="field-label">Policy version</span>
                    <span className="transaction-value mono-value">{preparedIntent.policyVersion}</span>
                  </div>
                  {authorizationTokenStates[preparedIntent.intentId] === "available" &&
                    !preparedIntentExpired && (
                      <p className="binding-help">
                        The one-time token is held only in volatile memory. It is never displayed or
                        persisted, and clears on expiry, wallet/account or agent changes, replacement,
                        or page refresh. No signing or transaction submission is available here.
                      </p>
                    )}
                  {authorizationTokenStates[preparedIntent.intentId] === "cleared" && (
                    <p className="binding-help">
                      The token has been cleared from this browser session and cannot be recovered.
                    </p>
                  )}
                  {authorizationTokenStates[preparedIntent.intentId] === "revoked" && (
                    <p className="binding-help">
                      SENTRA confirmed that this issued intent was revoked. It cannot be verified or reused.
                    </p>
                  )}
                  {authorizationTokenStates[preparedIntent.intentId] === "revocation-failed" && (
                    <p className="error-message" role="alert">
                      Server-side revocation could not be confirmed. This intent may remain valid until
                      its expiry; the local token was cleared and will not be retried automatically.
                    </p>
                  )}
                  {authorizationTokenStates[preparedIntent.intentId] === "not-retained" && (
                    <p className="binding-help">
                      The token was not retained because this session did not have a connected account
                      matching the expected signer. Only non-secret intent metadata remains visible.
                    </p>
                  )}
                  {(preparedIntentExpired ||
                    authorizationTokenStates[preparedIntent.intentId] === "expired") && (
                      <p className="binding-help">
                        The token expired and was cleared from memory. It cannot be recovered or
                        reused; re-evaluate the transaction before creating another intent.
                      </p>
                    )}
                </div>
              )}
            </>
          )}
        </section>

        {accountCheck && accountCheck.accountStatus !== "verified" && (
          <p className="verification-message" role="status">
            {accountCheck.message}
          </p>
        )}

        {errorMessage && (
          <p className="error-message" role="alert">
            {errorMessage}
          </p>
        )}

        <div className="wallet-actions">
          {!connected ? (
            <button
              className="primary-button"
              type="button"
              onClick={() => void connectWallet()}
              disabled={busy}
            >
              {status === "connecting" ? "Waiting for wallet…" : "Connect Wallet"}
            </button>
          ) : (
            <button
              className="secondary-button"
              type="button"
              onClick={() => void disconnectWallet()}
              disabled={busy}
            >
              {status === "disconnecting" ? "Disconnecting…" : "Disconnect"}
            </button>
          )}
          <span className="privacy-note">No keys or credentials are sent to SENTRA.</span>
        </div>

        <div className="security-note">
          <span className="note-icon" aria-hidden="true">i</span>
          <p>
            The Testnet RPC lookup confirms only whether this account exists on Testnet. NEAR
            Connect v0.12.0 exposes a requested network and wallet feature declarations, but no
            trusted active-network identity. SENTRA therefore keeps the wallet network Unverified.
            This milestone does not sign, authorize, execute or send transactions.
          </p>
        </div>
      </section>
      <footer className="page-footer">
        <span>SENTRA · AI can act. SENTRA keeps it accountable.</span>
        <span>Agent identity match does not verify active wallet network.</span>
      </footer>
    </main>
  );
}

export default App;
