import {
	McpServer,
	fromJsonSchema,
	type McpRequestContext
} from '@modelcontextprotocol/server';

import {
	mcpCatalogue,
	pathArgName,
	withheldConsoleOperations,
	type McpTool
} from './catalogue.js';
import { dispatchTool } from './dispatch.js';
import { annotationsFor, toOutcome, withheldOutcome } from './result.js';
import {
	CONFIRMATION_ARG,
	issueConfirmation,
	redeemConfirmation,
	targetKeyFor,
	REDEMPTION_MESSAGES
} from './confirm.js';
import { MCP_SERVER_NAME, MCP_RESOURCE } from './consts.js';

/*
 * Builds the MCP server for one request, registering a tool per catalogue entry.
 *
 * The registration loop reads the catalogue and nothing else, which is what keeps the published surface
 * and the table honest with each other: a tool cannot exist without an entry, and an entry that names a
 * route the console does not serve fails the drift guard.
 *
 * Input schemas come straight from the admin routes' own TypeBox objects. `fromJsonSchema` takes them
 * unchanged, so the schema an agent reads to build a call is the schema the route enforces — not a copy
 * of it that can drift.
 */

/* The credential the handler was called with, threaded to the tools that re-dispatch it. */
export interface McpCredential {
	readonly authorization: string;
	readonly dpop?: string;
}

/*
 * Path and query parameters are declared as plain strings alongside the body's properties, so a single
 * flat argument object describes the whole call. An agent should not have to know that `id` travels in
 * the path while `name` travels in the body.
 */
function inputSchemaFor(tool: McpTool): Record<string, unknown> {
	const properties: Record<string, unknown> = {};
	const required: string[] = [];

	for (const name of tool.pathParams) {
		const arg = pathArgName(tool, name);
		properties[arg] = {
			type: 'string',
			description: `Identifier of the ${arg === 'id' ? 'target' : arg}.`
		};
		required.push(arg);
	}

	if (tool.querySchema) {
		Object.assign(
			properties,
			(tool.querySchema.properties ?? {}) as Record<string, unknown>
		);
	}

	if (tool.bodySchema) {
		Object.assign(
			properties,
			(tool.bodySchema.properties ?? {}) as Record<string, unknown>
		);
		for (const name of (tool.bodySchema.required ?? []) as string[]) {
			required.push(name);
		}
	}

	/*
	 * High-consequence tools take the confirmation as an ordinary optional argument. Declared here rather
	 * than assumed, so an agent reading the schema can see how to confirm without being told separately.
	 */
	if (tool.consequence === 'high') {
		properties[CONFIRMATION_ARG] = {
			type: 'string',
			description:
				'Omit on the first call to receive a description of what would change plus a token. Pass the token back to perform exactly that operation.'
		};
	}

	/*
	 * Closed by default, so a mistyped argument is refused rather than silently dropped — and so the
	 * catalogue's no-passthrough guarantee has something to stand on.
	 *
	 * Open when the route's own body is an open map. `UpdateSettingsBody` is `t.Record(t.String(),
	 * t.Unknown())` — a partial map of setting key to value, validated per key by the handler against the
	 * catalog — so a closed tool schema refused every settings key before the handler ever saw it. Found
	 * by the confirmation matrix, where `settings_update` was the one tool that never reached its gate.
	 *
	 * Safe because openness is inherited from one fixed route's body, not from the caller: `dispatch.ts`
	 * only ever sends these fields as that route's body. A tool with path parameters is never opened —
	 * asserted by the drift guard — so an open object cannot smuggle a path segment.
	 */
	const bodyIsOpenMap =
		tool.bodySchema !== null &&
		Object.keys((tool.bodySchema.properties ?? {}) as object).length === 0;

	return {
		type: 'object',
		properties,
		...(required.length ? { required } : {}),
		additionalProperties: bodyIsOpenMap
	};
}

function describe(tool: McpTool): string {
	const parts = [tool.summary];
	if (tool.requiredRole) {
		parts.push(`Requires the ${tool.requiredRole} role.`);
	}
	if (tool.consequence === 'high') {
		parts.push(
			'High-consequence: called without a confirmationToken it changes nothing and returns a description of what it would do, plus a token to confirm that exact operation.'
		);
	}
	return parts.join(' ');
}

/*
 * The description a high-consequence tool returns instead of acting, on the first call.
 *
 * Built from the catalogue and the call's own arguments, and deliberately from nothing else: FR-017
 * forbids the description from disclosing anything the operator could not already read through an
 * ordinary read tool, and the surest way to honour that is to read nothing. Enriching a report with the
 * target's current state is a worthwhile follow-up, and it has to come with its own disclosure review.
 */
function consequenceReport(
	tool: McpTool,
	args: Record<string, unknown>
): Record<string, unknown> {
	return {
		tool: tool.tool,
		target: targetKeyFor(tool, args),
		effect: tool.summary,
		irreversible: tool.method === 'DELETE'
	};
}

/*
 * Who the admin plane says the caller is, asked once per gated call.
 *
 * Dispatches `GET /admin/api/me`, so the identity and roles are the ones `resolveAdmin` resolved for
 * this request — not a copy this module keeps. Both facts come from the one dispatch deliberately: the
 * role check and the principal binding were two separate `whoami` round-trips, which cost twice as much
 * and, worse, could disagree — a role revoked between them would pass the check and then bind a
 * confirmation to a caller the perform step will refuse.
 *
 * `null` on any failure, and callers must treat it as a refusal. An earlier version returned `''` for a
 * missing principal, which silently turned the confirmation's principal binding into a wildcard: two
 * callers whose lookup failed would both bind to `''`, so one operator's confirmation could be redeemed
 * by another. A binding that degrades to "matches anything" is worse than no binding, because it still
 * looks enforced.
 */
interface ResolvedCaller {
	readonly userId: string;
	readonly roles: readonly string[];
}

async function resolveCaller(
	credential: McpCredential
): Promise<ResolvedCaller | null> {
	const me = mcpCatalogue.find((t) => t.tool === 'whoami');
	// Fail closed. Unreachable while the drift guard requires `whoami` in the catalogue, but a lookup whose
	// fallback is "allow" is the wrong default to leave in a security path.
	if (!me) return null;
	const outcome = toOutcome(await dispatchTool(me, {}, credential));
	if (!outcome.ok) return null;
	const data = outcome.data as { userId?: string; roles?: string[] } | null;
	const userId = data?.userId;
	if (typeof userId !== 'string' || userId.length === 0) return null;
	return { userId, roles: data?.roles ?? [] };
}

/*
 * Whether the caller holds the role the tool documents. It exists so the describe step can refuse an
 * operation the caller could never perform, rather than handing out a confirmation that is certain to
 * fail (FR-017).
 *
 * It covers the role gate only. Finer-grained refusals — a project or bucket the caller does not manage
 * — need the entity itself and surface at the perform step, from the handler that owns the rule. That
 * is a worse message one step later, never a weaker check: nothing is performed without a confirmation
 * that the real route then authorizes for itself.
 */
function holdsRequiredRole(tool: McpTool, caller: ResolvedCaller): boolean {
	if (!tool.requiredRole) return true;
	return caller.roles.includes(tool.requiredRole);
}

/*
 * What a caller sees when either half of the confirmation's identity — the authorizing administrator or
 * the agent acting for them — cannot be established. Refuses rather than proceeding unbound.
 */
const UNRESOLVED_PRINCIPAL = {
	content: [
		{
			type: 'text' as const,
			text: 'could not establish which administrator authorized this call; nothing was done'
		}
	],
	structuredContent: {
		ok: false,
		reason: 'forbidden',
		message: 'the authorizing administrator could not be resolved'
	},
	isError: true
};

/*
 * Everything about a tool that does not depend on the request, compiled once for the process.
 *
 * The SDK calls the factory per exchange — deliberately, so nothing leaks between requests — but the
 * description, the annotations and above all the compiled input schema are the same on every call. Doing
 * them per request meant 39 `fromJsonSchema` compilations before a single tool ran, and it measured
 * **62ms against 0.15ms** for the admin route the tool wraps: a 410× overhead, found by
 * `test/mcp/latency.spec.ts` on its first run. Only the credential varies, so only the handler is built
 * per request.
 */
const REGISTRATIONS = mcpCatalogue.map((tool) => ({
	tool,
	config: {
		description: describe(tool),
		inputSchema: fromJsonSchema(
			inputSchemaFor(tool) as Parameters<typeof fromJsonSchema>[0]
		),
		annotations: annotationsFor(tool)
	}
}));

/* The instructions are static too, and reading the exclusion table on every request bought nothing. */
const INSTRUCTIONS = buildInstructions();

export function buildMcpServer(ctx: McpRequestContext): McpServer {
	const server = new McpServer(
		{ name: MCP_SERVER_NAME, version: '1.0.0' },
		{ instructions: INSTRUCTIONS }
	);

	const token = ctx.authInfo?.token;
	const credential: McpCredential | undefined = token
		? { authorization: `Bearer ${token}` }
		: undefined;

	for (const { tool, config } of REGISTRATIONS) {
		server.registerTool(
			tool.tool,
			config,

			/*
			 * The SDK infers a callback's argument type from its schema, and `fromJsonSchema` erases that
			 * to an opaque validator — so there is no inferred shape to annotate. Re-narrowed on the
			 * first line of the body, before anything reads it.
			 */
			// eslint-disable-next-line @typescript-eslint/no-explicit-any
			async (raw: any) => {
				const args = (raw ?? {}) as Record<string, unknown>;
				if (!credential) {
					// Unreachable through the mounted route, which refuses an unauthenticated request before
					// the handler is built. Kept so a future caller that forgets `authInfo` fails loudly
					// rather than dispatching with no principal.
					return {
						content: [{ type: 'text', text: 'authorization required' }],
						isError: true
					};
				}

				const withheld = withheldOutcome(tool.tool);
				if (withheld) {
					return {
						content: [{ type: 'text', text: withheld.message }],
						structuredContent: { ...withheld },
						isError: true
					};
				}

				const presented = args[CONFIRMATION_ARG];

				if (tool.consequence === 'high') {
					/*
					 * `principalId` is the administrator and `viaClientId` is the agent. Both are required,
					 * and neither may fall back to a placeholder: conflating them would let one operator's
					 * confirmation be spent by another working through the same agent, and defaulting either
					 * to `''` would make it match any caller whose id could not be read.
					 */
					const viaClientId = ctx.authInfo?.clientId;
					const caller = await resolveCaller(credential);
					if (!caller || !viaClientId) return UNRESOLVED_PRINCIPAL;

					const request = {
						tool,
						args,
						principalId: caller.userId,
						viaClientId,
						report: consequenceReport(tool, args)
					};

					if (typeof presented !== 'string' || presented.length === 0) {
						// Call one: describe, change nothing, and hand back a token bound to exactly this
						// operation. No audit entry — the trail records actions applied, and this applies none.
						if (!holdsRequiredRole(tool, caller)) {
							return {
								content: [
									{
										type: 'text',
										text: `forbidden: the ${tool.requiredRole} role is required, so this operation cannot be confirmed.`
									}
								],
								structuredContent: {
									ok: false,
									reason: 'forbidden',
									message: `the ${tool.requiredRole} role is required`
								},
								isError: true
							};
						}

						const issued = await issueConfirmation(request);
						return {
							content: [
								{
									type: 'text',
									text: `Nothing has been changed. ${tool.summary}\n\nTarget: ${issued.targetKey}\nTo proceed, call ${tool.tool} again with confirmationToken="${issued._id}". It is valid once, until ${issued.expiresAt.toISOString()}.`
								}
							],
							structuredContent: {
								status: 'confirmation_required',
								...issued.report,
								confirmationToken: issued._id,
								expiresAt: issued.expiresAt.toISOString()
							}
						};
					}

					// Call two: spend the token, or refuse. Every binding must match.
					const redemption = await redeemConfirmation(presented, request);
					if (!redemption.ok) {
						return {
							content: [
								{
									type: 'text',
									text: REDEMPTION_MESSAGES[redemption.failure]
								}
							],
							structuredContent: {
								ok: false,
								reason: 'invalid_confirmation',
								failure: redemption.failure,
								message: REDEMPTION_MESSAGES[redemption.failure]
							},
							isError: true
						};
					}
				} else if (typeof presented === 'string') {
					/*
					 * A token offered to a tool that has no gate is refused rather than ignored: a caller
					 * that believes it is confirming something must be told it is not.
					 *
					 * Defence in depth rather than the primary control. An ordinary tool does not declare
					 * `confirmationToken`, and every schema is `additionalProperties: false`, so the transport
					 * refuses such a call before this runs — measured in test/mcp/confirmation.spec.ts. This
					 * arm covers a caller that reaches a tool without schema validation.
					 */
					return {
						content: [
							{
								type: 'text',
								text: `${tool.tool} does not take a confirmation: it is not a high-consequence operation.`
							}
						],
						structuredContent: {
							ok: false,
							reason: 'invalid_request',
							message: 'this operation does not take a confirmation'
						},
						isError: true
					};
				}

				const outcome = toOutcome(await dispatchTool(tool, args, credential));

				if (!outcome.ok) {
					return {
						content: [
							{ type: 'text', text: `${outcome.reason}: ${outcome.message}` }
						],
						structuredContent: { ...outcome },
						isError: true
					};
				}

				return {
					content: [
						{ type: 'text', text: JSON.stringify(outcome.data, null, 2) }
					],
					structuredContent: { result: outcome.data }
				};
			}
		);
	}

	return server;
}

/*
 * Tells the agent up front what is withheld and where to do it instead.
 *
 * The withheld operations are deliberately NOT registered as tools that refuse: FR-031 says the surface
 * must not publish them, and a registered tool appears in `tools/list` however it behaves when called.
 * But an agent that only discovers the absence by guessing a name gets the transport's bare "unknown
 * tool", which leaves an operator unable to tell a withheld operation from a mistyped one (FR-034). The
 * server's instructions carry that knowledge instead, so the agent can answer correctly without a tool
 * existing — and the text is read from the catalogue's exclusion table, so it cannot disagree with it.
 */
function buildInstructions(): string {
	/*
	 * Both the list and the count come off the table. An earlier version named `project_delete` and
	 * `bucket_delete` literally, directly under a comment claiming the text could not disagree with the
	 * exclusion table — it could: a third withheld operation would have been added to the table, refused
	 * correctly when guessed, and silently left out of the announcement that exists so an agent does not
	 * have to guess. `inapplicable` entries stay out; see `absence` on the table for why.
	 */
	const withheld = withheldConsoleOperations
		.map((operation) => `- ${operation.reason}`)
		.join('\n');
	const n = withheldConsoleOperations.length;
	const count = n === 1 ? '1 operation that is' : `${n} operations that are`;

	return [
		`Administrative control plane for this OAuth 2.1 / OpenID Connect server (${MCP_RESOURCE}).`,
		'',
		'You act as the administrator who authorized this connection, with exactly their permissions. Every change is recorded in an immutable audit trail naming both them and this agent.',
		'',
		`The admin console can perform ${count} deliberately unavailable here. Do not attempt them, and if asked, say plainly that they must be done in the admin console:`,
		withheld,
		'',
		'Reading what such a deletion would involve IS available — a project reports the clients that block it, and a bucket reports how many end-users it holds.'
	].join('\n');
}
