import { createInterface } from "node:readline/promises";
import { stdin, stdout } from "node:process";
import { SentraDatabase, isValidNearAccountId } from "../database/database.js";

export async function provisionAgentWalletBinding(
  database: SentraDatabase,
  agentId: string,
  accountId: string,
  confirmReplacement: () => Promise<boolean>,
): Promise<void> {
  const agent = database.getAgent(agentId);
  if (!agent) {
    throw new Error(`Unknown SENTRA agent: ${agentId}`);
  }
  if (!isValidNearAccountId(accountId)) {
    throw new Error("Invalid NEAR testnet account ID.");
  }
  if (agent.authorizedNearAccountId === accountId) {
    throw new Error(`Agent ${agentId} is already bound to ${accountId}.`);
  }
  if (agent.authorizedNearAccountId !== null && !(await confirmReplacement())) {
    throw new Error("Existing wallet binding was not changed; confirmation required.");
  }

  const updated = database.setAgentAuthorizedNearAccount(agentId, accountId, {
    expectedCurrentAccountId: agent.authorizedNearAccountId,
  });
  if (!updated) {
    throw new Error(`Unknown SENTRA agent: ${agentId}`);
  }
}

async function main(): Promise<void> {
  const [agentId, accountId, ...extraArgs] = process.argv.slice(2);
  if (!agentId || !accountId || extraArgs.length > 0) {
    throw new Error(
      "Usage: npm run provision-wallet -- <agent-id> <near-testnet-account-id>",
    );
  }

  const database = new SentraDatabase();
  const prompt = createInterface({ input: stdin, output: stdout });
  try {
    const agent = database.getAgent(agentId);
    if (!agent) {
      throw new Error(`Unknown SENTRA agent: ${agentId}`);
    }

    stdout.write(`Agent ID: ${agent.id}\n`);
    stdout.write(`Current NEAR testnet account: ${agent.authorizedNearAccountId ?? "(unbound)"}\n`);
    stdout.write(`Requested NEAR testnet account: ${accountId}\n`);

    await provisionAgentWalletBinding(database, agentId, accountId, async () => {
      const answer = await prompt.question(
        "Changing an existing binding invalidates outstanding intents. Type REPLACE to confirm: ",
      );
      return answer === "REPLACE";
    });

    stdout.write(`Wallet binding saved for agent ${agentId}: ${accountId}\n`);
  } finally {
    prompt.close();
    database.close();
  }
}

if (require.main === module) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : "Wallet binding failed.";
    console.error(message);
    process.exitCode = 1;
  });
}
