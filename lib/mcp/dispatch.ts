import { Elysia } from 'elysia';

import { adminApiRoutes } from '../admin/routes.js';
import { ISSUER } from '../configs/env.js';
import { pathArgName, type McpTool } from './catalogue.js';
import { CONFIRMATION_ARG } from './confirm.js';

/*
 * The one way an agent's tool call reaches the control plane: build the HTTP request the console would
 * have sent, and hand it to the real admin routes in-process.
 *
 * This is what makes FR-004 structural rather than a promise kept by review. There is no service layer
 * a tool could call while skipping `assertRole`, no second validation, and no second audit write —
 * because there is no second implementation. A tool that wanted to bypass a check would have to stop
 * being a tool.
 *
 * Mounts `adminApiRoutes`, deliberately not `adminApp`: importing `adminApp` pulls `renderAdminShell`
 * and with it React and antd's CSS-in-JS, measured at ~86s to load against ~350ms for the route
 * plugins. The route set is identical either way — `adminApp` is this plus the HTML shell.
 *
 * `strictPath` and `normalize: false` mirror the root instance, so a path that would not match in
 * production does not match here either.
 */
const admin = new Elysia({ strictPath: true, normalize: false }).use(
	adminApiRoutes
);

export interface DispatchResult {
	readonly status: number;
	readonly body: unknown;
}

/*
 * Substitutes the tool call's path parameters into the route's declaration form. Each value is URI-
 * encoded: a client id may legitimately contain characters that would otherwise change which route
 * matches, or how many segments the path has.
 */
function buildPath(tool: McpTool, args: Record<string, unknown>): string {
	let path = tool.path;
	for (const name of tool.pathParams) {
		const arg = pathArgName(tool, name);
		const value = args[arg];
		if (typeof value !== 'string' || value.length === 0) {
			throw new Error(`missing path parameter: ${arg}`);
		}
		path = path.replace(`:${name}`, encodeURIComponent(value));
	}
	return path;
}

function buildQuery(tool: McpTool, args: Record<string, unknown>): string {
	if (!tool.querySchema) return '';
	const allowed = Object.keys(
		(tool.querySchema.properties ?? {}) as Record<string, unknown>
	);
	const params = new URLSearchParams();
	for (const name of allowed) {
		const value = args[name];
		if (value === undefined || value === null) continue;
		params.set(name, String(value));
	}
	const qs = params.toString();
	return qs ? `?${qs}` : '';
}

/*
 * The body is whatever the tool's arguments hold minus the ones consumed by the path, the query, and
 * the confirmation protocol. Built by subtraction rather than by copying an allow-list, because the
 * route's own schema is the authority on what it accepts — passing an unexpected field through and
 * letting the route refuse it is the behaviour FR-037 asks for, and it is why a field added to an admin
 * schema needs no change here.
 */
function buildBody(
	tool: McpTool,
	args: Record<string, unknown>
): unknown | undefined {
	if (!tool.bodySchema) return undefined;
	const consumed = new Set<string>([
		...tool.pathParams.map((name) => pathArgName(tool, name)),
		...Object.keys(
			(tool.querySchema?.properties ?? {}) as Record<string, unknown>
		),
		CONFIRMATION_ARG
	]);
	const body: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(args)) {
		if (!consumed.has(k) && v !== undefined) body[k] = v;
	}
	return body;
}

/*
 * Runs one tool's underlying admin route as the authenticated principal.
 *
 * The credential forwarded is the agent's own access token, unchanged. `resolveAdmin` validates it in
 * full — including that its audience is the MCP resource — and resolves the same AdminContext a console
 * session would. Nothing here asserts an identity; the token does, and it is checked.
 */
export async function dispatchTool(
	tool: McpTool,
	args: Record<string, unknown>,
	credential: { authorization: string; dpop?: string }
): Promise<DispatchResult> {
	const url = `${ISSUER.replace(/\/$/, '')}${buildPath(tool, args)}${buildQuery(tool, args)}`;
	const body = buildBody(tool, args);

	const headers: Record<string, string> = {
		authorization: credential.authorization,
		...(credential.dpop ? { dpop: credential.dpop } : {}),
		...(body !== undefined ? { 'content-type': 'application/json' } : {})
	};

	const response = await admin.handle(
		new Request(url, {
			method: tool.method,
			headers,
			...(body !== undefined ? { body: JSON.stringify(body) } : {})
		})
	);

	const text = await response.text();
	let parsed: unknown = undefined;
	if (text.length > 0) {
		try {
			parsed = JSON.parse(text);
		} catch {
			// A non-JSON body from an admin route would be a bug, but swallowing the parse and reporting
			// the text is more useful to an operator than an exception with no context.
			parsed = { error: 'unparseable_response', message: text.slice(0, 200) };
		}
	}

	return { status: response.status, body: parsed };
}
