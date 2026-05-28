import { createPublicKey, verify as nodeVerify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { KMSSigner } from "./signer.js";

/**
 * Real-KMS test. Skipped unless AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN is
 * set, so CI stays offline by default. Run it locally against a real
 * ECC_NIST_EDWARDS25519 KMS key with ambient credentials able to call
 * kms:Sign and kms:GetPublicKey:
 *
 *   AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN=arn:aws:kms:...:key/... \
 *       pnpm test
 */
const keyArn = process.env.AGENTRECEIPTS_AWS_KMS_INTEGRATION_KEY_ARN;

describe.skipIf(!keyArn)("KMSSigner integration", () => {
	it("signs a message that verifies against the KMS public key", async () => {
		const signer = new KMSSigner(keyArn as string, { timeoutMs: 15_000 });

		const raw = await signer.getPublicKey();
		expect(raw).toHaveLength(32);

		const publicKey = createPublicKey({
			key: {
				kty: "OKP",
				crv: "Ed25519",
				x: Buffer.from(raw).toString("base64url"),
			},
			format: "jwk",
		});

		const message = Buffer.from("agent-receipts kms integration test message");
		const sig = await signer.sign(message);

		expect(nodeVerify(null, message, publicKey, sig)).toBe(true);
	});
});
