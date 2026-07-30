import { invokeTauri } from "@/shared/api/tauri";

export async function attestExternalAgent(
  agentPubkey: string,
): Promise<string> {
  return invokeTauri<string>("attest_external_agent", { agentPubkey });
}

export function normalizeExternalAgentPubkey(input: string): string {
  const pubkey = input.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(pubkey)) {
    throw new Error("Enter a valid 64-character hex public key.");
  }
  return pubkey;
}

export async function createExternalAgentAuthTag(
  input: string,
  attest: (pubkey: string) => Promise<string>,
): Promise<string> {
  return attest(normalizeExternalAgentPubkey(input));
}
