import express, {
  type ErrorRequestHandler,
  type Response,
} from "express";
import { z } from "zod";
import { SentraDatabase } from "../database/database.js";
import { SentraService, ServiceError } from "../services/sentraService.js";
import {
  TransactionAuthorizationError,
  TransactionAuthorizationService,
  type TransactionVerifier,
} from "../services/transactionAuthorizationService.js";
import { THREAT_SCENARIOS, ThreatLabService } from "../services/threatLabService.js";

const accountIdPattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const yoctoAmountSchema = z.string().refine(
  (value) => /^\d+$/.test(value) && BigInt(value) > 0n,
);
const accountIdSchema = z
  .string()
  .min(2)
  .max(64)
  .regex(accountIdPattern);

const agentCreateSchema = z
  .object({
    name: z.string().trim().min(1).max(120),
    description: z.string().max(2000).optional().default(""),
  })
  .strict();

const agentUpdateSchema = z.object({ enabled: z.boolean() }).strict();

const policyUpdateSchema = z
  .object({
    maxTransactionAmountYocto: yoctoAmountSchema,
    approvalThresholdYocto: yoctoAmountSchema,
    deniedRecipients: z.array(accountIdSchema).max(1000),
  })
  .strict()
  .superRefine((policy, context) => {
    const amountsAreIntegers =
      /^\d+$/.test(policy.approvalThresholdYocto) &&
      /^\d+$/.test(policy.maxTransactionAmountYocto);
    if (
      amountsAreIntegers &&
      BigInt(policy.approvalThresholdYocto) > BigInt(policy.maxTransactionAmountYocto)
    ) {
      context.addIssue({
        code: "custom",
        path: ["approvalThresholdYocto"],
        message: "Approval threshold must not exceed the maximum transaction amount.",
      });
    }
  });

const transactionProposalSchema = z
  .object({
    agentId: z.string().min(1).optional(),
    network: z.string(),
    transactionType: z.string(),
    recipient: z.string(),
    amountYocto: z.string(),
    asset: z.string(),
    reason: z.string().max(2000),
  })
  .strict();

const evaluationSchema = z
  .object({
    agentId: z.string().min(1),
    transaction: transactionProposalSchema,
  })
  .strict();

const prepareTransactionSchema = z.object({}).strict();
const confirmTransactionSchema = z
  .object({
    intentId: z.string().trim().min(1).max(100),
    authorizationToken: z.string().min(1).max(128),
    transactionHash: z.string().min(1).max(64),
  })
  .strict();
const revokeAuthorizationSchema = z
  .object({
    authorizationToken: z.string().min(1).max(128),
  })
  .strict();

const approvalReviewSchema = z
  .object({
    reviewer: z.string().trim().min(1).max(120),
    rejectionReason: z.string().trim().min(1).max(2000).optional(),
  })
  .strict();

const approvalRejectSchema = approvalReviewSchema.extend({
  rejectionReason: z.string().trim().min(1).max(2000),
});

const threatSimulationSchema = z
  .object({
    agentId: z.string().min(1),
    scenarioId: z
      .string()
      .refine((id) => THREAT_SCENARIOS.some((scenario) => scenario.id === id)),
  })
  .strict();

function sendValidationError(response: Response, error: z.ZodError): void {
  response.status(400).json({
    error: {
      code: "INVALID_INPUT",
      message: "Request validation failed.",
      details: error.issues.map((issue) => ({
        path: issue.path.join("."),
        message: issue.message,
      })),
    },
  });
}

function sendParsed<T>(
  response: Response,
  parsed: { success: true; data: T } | { success: false; error: z.ZodError },
): T | undefined {
  if (!parsed.success) {
    sendValidationError(response, parsed.error);
    return undefined;
  }
  return parsed.data;
}

export function createApp(
  database: SentraDatabase,
  transactionVerifier?: TransactionVerifier,
): express.Express {
  const app = express();
  const service = new SentraService(database);
  const authorizationService = new TransactionAuthorizationService(
    database,
    transactionVerifier,
  );
  const threatLabService = new ThreatLabService(database);
  app.disable("x-powered-by");
  app.use(express.json({ limit: "32kb" }));

  app.get("/api/health", (_request, response) => {
    response.json({ status: "ok", message: "SENTRA backend is running" });
  });

  app.get("/api/threat-lab/scenarios", (_request, response) => {
    response.json({ data: threatLabService.listScenarios() });
  });

  app.post("/api/threat-lab/simulate", (request, response) => {
    const body = sendParsed(response, threatSimulationSchema.safeParse(request.body));
    if (!body) return;
    response.status(201).json({ data: threatLabService.simulate(body.agentId, body.scenarioId) });
  });

  app.get("/api/agents", (_request, response) => {
    response.json({ data: service.listAgents() });
  });

  app.post("/api/agents", (request, response) => {
    const body = sendParsed(response, agentCreateSchema.safeParse(request.body));
    if (!body) return;
    response.status(201).json({ data: service.registerAgent(body.name, body.description) });
  });

  app.get("/api/agents/:agentId", (request, response) => {
    response.json({ data: service.getAgent(request.params.agentId) });
  });

  app.patch("/api/agents/:agentId", (request, response) => {
    const body = sendParsed(response, agentUpdateSchema.safeParse(request.body));
    if (!body) return;
    response.json({ data: service.setAgentEnabled(request.params.agentId, body.enabled) });
  });

  app.get("/api/agents/:agentId/policy", (request, response) => {
    response.json({ data: service.getPolicy(request.params.agentId) });
  });

  app.put("/api/agents/:agentId/policy", (request, response) => {
    const body = sendParsed(response, policyUpdateSchema.safeParse(request.body));
    if (!body) return;
    response.json({ data: service.updatePolicy(request.params.agentId, body) });
  });

  app.post("/api/transactions/evaluate", (request, response) => {
    const body = sendParsed(response, evaluationSchema.safeParse(request.body));
    if (!body) return;
    response.status(201).json({ data: service.evaluate(body.agentId, body.transaction) });
  });

  app.post("/api/transactions/:transactionId/prepare", (request, response) => {
    const body = sendParsed(
      response,
      prepareTransactionSchema.safeParse(request.body ?? {}),
    );
    if (!body) return;
    response.status(201).json({
      data: authorizationService.prepare(request.params.transactionId),
    });
  });

  app.post("/api/authorization-intents/:intentId/revoke", (request, response) => {
    const body = sendParsed(response, revokeAuthorizationSchema.safeParse(request.body));
    if (!body) return;
    response.json({
      data: authorizationService.revoke(request.params.intentId, body.authorizationToken),
    });
  });

  app.post("/api/transactions/confirm", async (request, response) => {
    const body = sendParsed(response, confirmTransactionSchema.safeParse(request.body));
    if (!body) return;
    response.json({
      data: await authorizationService.confirm(
        body.intentId,
        body.authorizationToken,
        body.transactionHash,
      ),
    });
  });

  app.get("/api/transactions", (_request, response) => {
    response.json({ data: service.listTransactions() });
  });

  app.get("/api/transactions/:transactionId", (request, response) => {
    response.json({ data: service.getTransaction(request.params.transactionId) });
  });

  app.get("/api/approvals", (_request, response) => {
    response.json({ data: service.listApprovals() });
  });

  app.get("/api/approvals/:approvalId", (request, response) => {
    response.json({ data: service.getApproval(request.params.approvalId) });
  });

  const approveHandler = (request: express.Request<{ approvalId: string }>, response: Response) => {
    const body = sendParsed(response, approvalReviewSchema.safeParse(request.body));
    if (!body) return;
    if (body.rejectionReason !== undefined) {
      response.status(400).json({
        error: {
          code: "INVALID_INPUT",
          message: "rejectionReason is only accepted when rejecting an approval.",
        },
      });
      return;
    }
    response.json({
      data: service.reviewApproval(
        request.params.approvalId,
        "approved",
        body.reviewer,
      ),
    });
  };
  app.post("/api/approvals/:approvalId/approve", approveHandler);

  app.post("/api/approvals/:approvalId/reject", (request, response) => {
    const body = sendParsed(response, approvalRejectSchema.safeParse(request.body));
    if (!body) return;
    response.json({
      data: service.reviewApproval(
        request.params.approvalId,
        "rejected",
        body.reviewer,
        body.rejectionReason,
      ),
    });
  });

  app.get("/api/audit", (_request, response) => {
    response.json({ data: service.listAudit() });
  });

  app.use((_request, response) => {
    response.status(404).json({
      error: { code: "NOT_FOUND", message: "API resource not found." },
    });
  });

  const errorHandler: ErrorRequestHandler = (error: unknown, _request, response, _next) => {
    if (error instanceof TransactionAuthorizationError) {
      response.status(error.statusCode).json({
        error: { code: error.code, message: error.message },
      });
      return;
    }
    if (error instanceof ServiceError) {
      response.status(error.statusCode).json({
        error: { code: error.code, message: error.message },
      });
      return;
    }
    if (error instanceof SyntaxError && "body" in error) {
      response.status(400).json({
        error: { code: "INVALID_JSON", message: "Request body must contain valid JSON." },
      });
      return;
    }
    if (response.headersSent) return;
    console.error("Unexpected API error:", error);
    response.status(500).json({
      error: { code: "INTERNAL_ERROR", message: "An unexpected server error occurred." },
    });
  };
  app.use(errorHandler);

  return app;
}
