import { generateKeyPair, type KeyPair } from "./signing.js";

/**
 * Environment variable that marks a production deployment. A
 * {@link GeneratingKeyProvider} refuses to run when it is set to the exact
 * value `"true"` (see ADR-0018 § Key generation policy and ADR-0019 § S2).
 */
const PRODUCTION_ENV_VAR = "AGENTRECEIPTS_PRODUCTION";

/** The one-line, dev-only warning emitted at most once per process. */
const DEV_WARNING =
	"⚠ GeneratingKeyProvider is dev-only — set AGENTRECEIPTS_PRODUCTION=true to disable in production\n";

/**
 * Thrown when a {@link GeneratingKeyProvider} is constructed in a production
 * deployment (`AGENTRECEIPTS_PRODUCTION=true`).
 *
 * Generating a keypair on the fly mints a fresh DID on every cold start,
 * producing an unverifiable audit trail with no error surfaced. Production
 * deployments must provision a keypair out-of-band and load it via a file,
 * env-var, or secret-store key provider. See the ephemeral-compute deployment
 * guide.
 */
export class ProductionKeyProviderError extends Error {
	constructor(
		message = "GeneratingKeyProvider is disabled in production (AGENTRECEIPTS_PRODUCTION=true): provision a keypair out-of-band and load it via a file, env-var, or secret-store key provider",
	) {
		super(message);
		this.name = "ProductionKeyProviderError";
	}
}

/**
 * Supplies the Ed25519 keypair the SDK signs with. Models environments where
 * the private key bytes are accessible locally (files, env vars, in-memory
 * fixtures). Environments where the private key is never extractable (KMS,
 * HSM, TPM) implement `Signer` instead (see ADR-0018).
 */
export interface KeyProvider {
	getKeyPair(): Promise<KeyPair>;
}

// One stderr warning per process, regardless of how many providers are built.
let devWarningEmitted = false;

function isProduction(): boolean {
	return process.env[PRODUCTION_ENV_VAR] === "true";
}

/**
 * Generates a fresh Ed25519 keypair for development and bootstrap use only.
 * The keypair is stable for the lifetime of the provider.
 *
 * It is explicitly prohibited in production: constructing one when
 * `AGENTRECEIPTS_PRODUCTION=true` throws {@link ProductionKeyProviderError}
 * before any key is generated.
 */
export class GeneratingKeyProvider implements KeyProvider {
	private readonly keyPair: KeyPair;

	constructor() {
		if (isProduction()) {
			throw new ProductionKeyProviderError();
		}
		if (!devWarningEmitted) {
			devWarningEmitted = true;
			process.stderr.write(DEV_WARNING);
		}
		this.keyPair = generateKeyPair();
	}

	getKeyPair(): Promise<KeyPair> {
		return Promise.resolve({ ...this.keyPair });
	}
}
