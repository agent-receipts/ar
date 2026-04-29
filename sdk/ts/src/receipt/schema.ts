/**
 * Zod runtime schemas mirroring the interfaces in types.ts.
 *
 * Every object uses .passthrough() so unknown extra fields written by a newer
 * SDK are preserved on load — required for forward-compatibility of canonical
 * JSON / signature verification, since stripping unknown keys would break the
 * RFC 8785 hash on receipts written by future SDK versions.
 */
import { z } from "zod";
import type { AgentReceipt } from "./types.js";

// --- Risk levels ---

const riskLevelSchema = z.enum(["low", "medium", "high", "critical"]);

// --- Outcome status ---

const outcomeStatusSchema = z.enum(["success", "failure", "pending"]);

// --- Issuer ---

const operatorSchema = z
	.object({
		id: z.string(),
		name: z.string(),
	})
	.passthrough();

const issuerSchema = z
	.object({
		id: z.string(),
		type: z.string().optional(),
		name: z.string().optional(),
		operator: operatorSchema.optional(),
		model: z.string().optional(),
		session_id: z.string().optional(),
	})
	.passthrough();

// --- Principal ---

const principalSchema = z
	.object({
		id: z.string(),
		type: z.string().optional(),
	})
	.passthrough();

// --- Action ---

const actionTargetSchema = z
	.object({
		system: z.string(),
		resource: z.string().optional(),
	})
	.passthrough();

const actionSchema = z
	.object({
		id: z.string(),
		type: z.string(),
		tool_name: z.string().optional(),
		risk_level: riskLevelSchema,
		target: actionTargetSchema.optional(),
		parameters_hash: z.string().optional(),
		parameters_preview: z.record(z.string()).optional(),
		timestamp: z.string(),
		trusted_timestamp: z.string().optional(),
	})
	.passthrough();

// --- Intent ---

const intentSchema = z
	.object({
		conversation_hash: z.string().optional(),
		prompt_preview: z.string().optional(),
		prompt_preview_truncated: z.boolean().optional(),
		reasoning_hash: z.string().optional(),
	})
	.passthrough();

// --- Outcome ---

const stateChangeSchema = z
	.object({
		before_hash: z.string(),
		after_hash: z.string(),
	})
	.passthrough();

const outcomeSchema = z
	.object({
		status: outcomeStatusSchema,
		error: z.string().optional(),
		reversible: z.boolean().optional(),
		reversal_method: z.string().optional(),
		reversal_window_seconds: z.number().optional(),
		state_change: stateChangeSchema.optional(),
		response_hash: z.string().optional(),
	})
	.passthrough();

// --- Authorization ---

const authorizationSchema = z
	.object({
		scopes: z.array(z.string()),
		granted_at: z.string(),
		expires_at: z.string().optional(),
		grant_ref: z.string().optional(),
	})
	.passthrough();

// --- Chain ---

const chainSchema = z
	.object({
		sequence: z.number(),
		previous_receipt_hash: z.string().nullable(),
		chain_id: z.string(),
		// When present, MUST be true. Explicit false is not valid per the spec.
		terminal: z.literal(true).optional(),
	})
	.passthrough();

// --- Credential Subject ---

const credentialSubjectSchema = z
	.object({
		principal: principalSchema,
		action: actionSchema,
		intent: intentSchema.optional(),
		outcome: outcomeSchema,
		authorization: authorizationSchema.optional(),
		chain: chainSchema,
	})
	.passthrough();

// --- Proof ---

const proofSchema = z
	.object({
		type: z.string(),
		created: z.string().optional(),
		verificationMethod: z.string().optional(),
		proofPurpose: z.string().optional(),
		proofValue: z.string(),
	})
	.passthrough();

// --- Agent Receipt ---

// Annotated as ZodType<AgentReceipt> so .parse() returns AgentReceipt directly
// at the call site, avoiding an `as` cast at the validation boundary.
export const agentReceiptSchema: z.ZodType<AgentReceipt> = z
	.object({
		"@context": z.array(z.string()),
		id: z.string(),
		type: z.array(z.string()),
		version: z.string(),
		issuer: issuerSchema,
		issuanceDate: z.string(),
		credentialSubject: credentialSubjectSchema,
		proof: proofSchema,
	})
	.passthrough();
