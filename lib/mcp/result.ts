import type { DeletionBlocker } from '../admin/auth/rbac.js';
import { excludedOperationFor, type McpTool } from './catalogue.js';
import type { DispatchResult } from './dispatch.js';

/*
 * Turns an admin-plane response into an MCP tool result.
 *
 * The distinction FR-024 asks for is preserved rather than collapsed into one failure: an agent that
 * cannot tell "you may not" from "it does not exist" from "your input is wrong" will retry the wrong
 * thing, and an operator reading its account of events will be misled about what happened.
 */

export type Reason =
	| 'forbidden'
	| 'not_found'
	| 'conflict'
	| 'invalid_request'
	| 'partial_failure'
	| 'not_available_here'
	| 'server_error';

export interface ToolFailure {
	readonly ok: false;
	readonly reason: Reason;
	readonly message: string;
	readonly blockers?: readonly DeletionBlocker[];
	readonly failedAreas?: readonly string[];
}

export interface ToolSuccess {
	readonly ok: true;
	readonly data: unknown;
}

export type ToolOutcome = ToolSuccess | ToolFailure;

const BY_STATUS: Record<number, Reason> = {
	400: 'invalid_request',
	403: 'forbidden',
	404: 'not_found',
	409: 'conflict',
	422: 'invalid_request'
};

interface AdminErrorBody {
	error?: string;
	message?: string;
	blockers?: readonly DeletionBlocker[];
	failedAreas?: readonly string[];
}

export function toOutcome(result: DispatchResult): ToolOutcome {
	if (result.status >= 200 && result.status < 300) {
		return { ok: true, data: result.body };
	}

	const body = (result.body ?? {}) as AdminErrorBody;
	const message = body.message ?? 'the operation was refused';

	if (result.status === 500 && body.failedAreas?.length) {
		/*
		 * The principal was destroyed but a sweep failed afterwards. Reported as its own reason because
		 * an agent must not describe this as success, and must not describe it as a clean failure either
		 * — something did happen, and an operator needs to know which areas were left behind.
		 */
		return {
			ok: false,
			reason: 'partial_failure',
			message,
			failedAreas: body.failedAreas
		};
	}

	const reason = BY_STATUS[result.status] ?? 'server_error';

	return {
		ok: false,
		reason,
		message,
		// Passed through verbatim, counts and ids exactly as the admin plane discloses them: a project's
		// clients are named because they are objects the operator administers, a bucket's end-users are
		// only counted because their identities are not the caller's business.
		...(body.blockers ? { blockers: body.blockers } : {})
	};
}

/*
 * The refusal for an operation the console can perform but agents cannot.
 *
 * Distinct from `forbidden` on purpose, and the distinction is the point of FR-034: told "forbidden",
 * an operator goes looking for the role that would unlock it, and there is none — no role does. The
 * reason text comes from the catalogue's exclusion table so the message and the table cannot disagree.
 */
export function withheldOutcome(toolName: string): ToolFailure | undefined {
	const excluded = excludedOperationFor(toolName);
	if (!excluded) return undefined;
	return {
		ok: false,
		reason: 'not_available_here',
		message: excluded.reason
	};
}

/* The MCP advisory annotations for a tool, derived from its consequence class rather than restated. */
export function annotationsFor(tool: McpTool): {
	readOnlyHint: boolean;
	destructiveHint: boolean;
	idempotentHint: boolean;
} {
	return {
		readOnlyHint: tool.consequence === 'read',
		destructiveHint:
			tool.method === 'DELETE' || tool.tool === 'admin_deactivate',
		idempotentHint: tool.method === 'PATCH' || tool.method === 'PUT'
	};
}
