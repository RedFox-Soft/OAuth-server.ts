import { Type, type Static } from '@sinclair/typebox';
import { elysia } from 'lib/index.ts';
import { MCP_ROUTE } from 'lib/mcp/consts.ts';
import { shaped } from '../shape.ts';

/*
 * A JSON-RPC exchange with /mcp, as an agent's client makes it: one POST, answered either as plain JSON
 * or as a server-sent event whose `data:` line carries the message. The members are the ones the specs
 * read, checked rather than claimed (test/shape.ts); anything else a message carries is admitted.
 */

/* What a tool call answers in structuredContent: its result, a confirmation it asks for, or a refusal. */
const StructuredContent = Type.Object({
	result: Type.Optional(Type.Unknown()),
	ok: Type.Optional(Type.Boolean()),
	status: Type.Optional(Type.String()),
	confirmationToken: Type.Optional(Type.String()),
	target: Type.Optional(Type.String()),
	reason: Type.Optional(Type.String()),
	message: Type.Optional(Type.String()),
	failure: Type.Optional(Type.Unknown())
});

const McpResult = Type.Object({
	isError: Type.Optional(Type.Boolean()),
	content: Type.Optional(
		Type.Array(
			Type.Object({ type: Type.String(), text: Type.Optional(Type.String()) })
		)
	),
	structuredContent: Type.Optional(StructuredContent),
	tools: Type.Optional(
		Type.Array(
			Type.Object({
				name: Type.String(),
				inputSchema: Type.Optional(Type.Unknown())
			})
		)
	),
	instructions: Type.Optional(Type.String()),
	serverInfo: Type.Optional(Type.Object({ name: Type.String() }))
});

const McpMessage = Type.Object({
	jsonrpc: Type.Literal('2.0'),
	id: Type.Optional(Type.Union([Type.Number(), Type.String(), Type.Null()])),
	result: Type.Optional(McpResult),
	error: Type.Optional(
		Type.Object({
			code: Type.Number(),
			message: Type.String(),
			data: Type.Optional(Type.Unknown())
		})
	)
});
export type McpMessage = Static<typeof McpMessage>;

/* The exchange itself: the status, the body as sent, and the message in it when there is one. */
export async function postMcp(
	body: unknown,
	token?: string
): Promise<{ status: number; raw: string; message: McpMessage | undefined }> {
	const res = await elysia.handle(
		new Request(`http://e.ly${MCP_ROUTE}`, {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				accept: 'application/json, text/event-stream',
				...(token ? { authorization: `Bearer ${token}` } : {})
			},
			body: JSON.stringify(body)
		})
	);
	const raw = await res.text();
	const isEvent = (res.headers.get('content-type') ?? '').includes(
		'text/event-stream'
	);
	const json = isEvent
		? raw
				.split('\n')
				.find((l) => l.startsWith('data:'))
				?.slice('data:'.length)
				.trim()
		: raw;
	const message = json
		? shaped(McpMessage, JSON.parse(json) as unknown)
		: undefined;
	return { status: res.status, raw, message };
}

/* One request that must be answered with a JSON-RPC message. */
export async function rpc(body: unknown, token: string): Promise<McpMessage> {
	const { status, message } = await postMcp(body, token);
	if (!message) throw new Error(`expected a JSON-RPC message, got ${status}`);
	return message;
}

let rpcId = 0;

/* A tools/call request, numbered so a response can be told from another. */
export function call(name: string, args: Record<string, unknown> = {}) {
	return {
		jsonrpc: '2.0',
		id: ++rpcId,
		method: 'tools/call',
		params: { name, arguments: args }
	};
}
