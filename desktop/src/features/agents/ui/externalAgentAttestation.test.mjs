import assert from "node:assert/strict";
import test from "node:test";

import {
  createExternalAgentAuthTag,
  normalizeExternalAgentPubkey,
} from "./externalAgentAttestation.ts";

const PUBKEY = "a".repeat(64);

test("normalizes a valid external agent public key", () => {
  assert.equal(
    normalizeExternalAgentPubkey(`  ${PUBKEY.toUpperCase()}  `),
    PUBKEY,
  );
});

test("rejects malformed external agent public keys before invoking Tauri", async () => {
  let calls = 0;
  await assert.rejects(
    createExternalAgentAuthTag("not-a-pubkey", async () => {
      calls += 1;
      return "unused";
    }),
    /64-character hex public key/,
  );
  assert.equal(calls, 0);
});

test("invokes attestation with the normalized key and returns the auth tag", async () => {
  const seen = [];
  const result = await createExternalAgentAuthTag(
    ` ${PUBKEY.toUpperCase()} `,
    async (pubkey) => {
      seen.push(pubkey);
      return "signed-auth-tag";
    },
  );

  assert.deepEqual(seen, [PUBKEY]);
  assert.equal(result, "signed-auth-tag");
});

test("surfaces attestation failures", async () => {
  await assert.rejects(
    createExternalAgentAuthTag(PUBKEY, async () => {
      throw new Error("owner identity is locked");
    }),
    /owner identity is locked/,
  );
});
