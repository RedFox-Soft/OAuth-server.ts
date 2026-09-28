/*
 * The in-process channel from the agent surface to the management API, and the only place an agent's
 * token is accepted there.
 *
 * What an agent may not do is decided in the `/mcp` transport: the operations withheld from it are not
 * published, and a destructive one asks for confirmation. The management API itself is publicly
 * mounted, so a token it accepted from the network would skip both — and an agent able to make an HTTP
 * request, following instructions injected into data it had read, could delete a project or permit
 * another client identity with nothing but its own credential.
 *
 * A membership test on the Request object rather than a header, because nothing arriving from the
 * network can be put in this set: the server constructs every request it receives, and only
 * `dispatchTool` adds one. Weak, so a finished request is not kept alive by having been marked.
 *
 * Imports nothing, so `lib/admin/auth/rbac.ts` can reach it without the model graph behind
 * `lib/mcp/principal.ts`.
 */
const dispatched = new WeakSet<Request>();

export function markDispatched(request: Request): Request {
	dispatched.add(request);
	return request;
}

export function isDispatched(request: Request): boolean {
	return dispatched.has(request);
}
