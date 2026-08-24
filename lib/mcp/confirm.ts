import crypto from 'node:crypto';

import { mcpConfirmationStore } from '../adapters/index.js';
import type { McpConfirmation } from '../adapters/types.js';
import { pathArgName, type McpTool } from './catalogue.js';
import { MCP_CONFIRMATION_TTL_SECONDS } from './consts.js';

/*
 * The server-side half of the two-step gate on high-consequence operations.
 *
 * A client-side "are you sure" is not a control this server can rely on: an agent's interface is not
 * ours, and a compromised or simply eager client would skip it. So the gate is a property of the
 * surface — call one describes and performs nothing, call two performs — and the binding between them
 * is enforced here.
 */

export const CONFIRMATION_ARG = 'confirmationToken';

/*
 * Canonicalised so that re-serialising the same arguments in a different key order still matches. Without
 * this, a legitimate confirmation would be refused whenever the agent happened to emit its JSON
 * differently on the second call — which turns a security control into a source of flakes, and pressure
 * to weaken it.
 *
 * The confirmation token itself is excluded: it is not part of the operation being described.
 */
export function canonicalArgumentsHash(args: Record<string, unknown>): string {
	const entries = Object.entries(args)
		.filter(([key, value]) => key !== CONFIRMATION_ARG && value !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	const canonical = JSON.stringify(entries);
	return crypto.createHash('sha256').update(canonical).digest('hex');
}

/*
 * The target, as a path a person can read. It appears in the refusal when a confirmation is presented
 * for a different entity, so an operator can see at a glance that the agent aimed somewhere else.
 */
export function targetKeyFor(
	tool: McpTool,
	args: Record<string, unknown>
): string {
	if (tool.pathParams.length === 0) return tool.tool;
	return tool.pathParams
		.map((name) => {
			const arg = pathArgName(tool, name);
			return `${arg}=${String(args[arg])}`;
		})
		.join('/');
}

export interface ConfirmationRequest {
	readonly tool: McpTool;
	readonly args: Record<string, unknown>;
	readonly principalId: string;
	readonly viaClientId: string;
	readonly report: Record<string, unknown>;
}

export async function issueConfirmation(
	request: ConfirmationRequest
): Promise<McpConfirmation> {
	return mcpConfirmationStore.issue({
		tool: request.tool.tool,
		targetKey: targetKeyFor(request.tool, request.args),
		argumentsHash: canonicalArgumentsHash(request.args),
		principalId: request.principalId,
		viaClientId: request.viaClientId,
		report: request.report,
		ttlSeconds: MCP_CONFIRMATION_TTL_SECONDS
	});
}

export type RedemptionFailure =
	| 'unknown_or_spent'
	| 'wrong_tool'
	| 'wrong_target'
	| 'arguments_changed'
	| 'wrong_principal'
	| 'wrong_agent';

export type Redemption =
	| { readonly ok: true; readonly record: McpConfirmation }
	| { readonly ok: false; readonly failure: RedemptionFailure };

/*
 * Spends a confirmation, or refuses it.
 *
 * The record is deleted by `redeem` *before* any binding is checked, and that ordering is deliberate:
 * a token presented for the wrong operation has still been presented, and leaving it live would let a
 * caller probe the bindings one at a time. A mismatch therefore costs the token — the operator confirms
 * again, which is the safe direction.
 *
 * Expiry and non-existence are indistinguishable here, by design: neither is redeemable, and telling
 * them apart would only help someone guessing.
 */
export async function redeemConfirmation(
	token: string,
	request: ConfirmationRequest
): Promise<Redemption> {
	const record = await mcpConfirmationStore.redeem(token);
	if (!record) return { ok: false, failure: 'unknown_or_spent' };

	if (record.tool !== request.tool.tool) {
		return { ok: false, failure: 'wrong_tool' };
	}
	if (record.targetKey !== targetKeyFor(request.tool, request.args)) {
		return { ok: false, failure: 'wrong_target' };
	}
	if (record.argumentsHash !== canonicalArgumentsHash(request.args)) {
		return { ok: false, failure: 'arguments_changed' };
	}
	if (record.principalId !== request.principalId) {
		return { ok: false, failure: 'wrong_principal' };
	}
	if (record.viaClientId !== request.viaClientId) {
		return { ok: false, failure: 'wrong_agent' };
	}

	return { ok: true, record };
}

/* What each refusal tells the operator. Named so the message and the failure cannot drift apart. */
export const REDEMPTION_MESSAGES: Record<RedemptionFailure, string> = {
	unknown_or_spent:
		'that confirmation is not valid: it was already used, or it has expired. Ask again to get a fresh description and token.',
	wrong_tool: 'that confirmation was issued for a different operation.',
	wrong_target: 'that confirmation was issued for a different target.',
	arguments_changed:
		'the parameters differ from the ones that were described and confirmed.',
	wrong_principal: 'that confirmation was issued to a different administrator.',
	wrong_agent: 'that confirmation was issued to a different agent.'
};
