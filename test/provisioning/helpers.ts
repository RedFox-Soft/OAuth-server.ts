import { elysia } from 'lib/index.js';
import { isRecord } from 'lib/helpers/_/object.ts';

/*
 * The admin API and the token endpoint as a console and a directory reach them: over HTTP, through the real
 * application, so authorization, validation, audit and the token endpoint's own client authentication all
 * run as they do in production.
 */

export interface Reply {
	status: number;
	// The parsed body as it came. A list route answers an array: read it from here, through shaped().
	body: unknown;
	// The body when it is an object, as nearly every route answers; empty when it is not one.
	json: Record<string, unknown>;
}

async function read(response: Response): Promise<Reply> {
	const text = await response.text();
	let body: unknown;
	try {
		body = text ? JSON.parse(text) : {};
	} catch {
		body = { raw: text };
	}
	return { status: response.status, body, json: isRecord(body) ? body : {} };
}

export async function admin(
	method: string,
	path: string,
	cookie: string,
	body?: unknown
): Promise<Reply> {
	return read(
		await elysia.handle(
			new Request(`http://e.ly${path}`, {
				method,
				headers: {
					cookie,
					...(body === undefined ? {} : { 'content-type': 'application/json' })
				},
				body: body === undefined ? undefined : JSON.stringify(body)
			})
		)
	);
}

/* A client-credentials request at a bucket's token endpoint (`/<slug>/token`, or `/token` at the root). */
export async function token(
	path: string,
	form: Record<string, string>,
	headers: Record<string, string> = {}
): Promise<Reply> {
	return read(
		await elysia.handle(
			new Request(`http://e.ly${path}`, {
				method: 'POST',
				headers: {
					'content-type': 'application/x-www-form-urlencoded',
					...headers
				},
				body: new URLSearchParams(form).toString()
			})
		)
	);
}

export function basic(
	clientId: string,
	secret: string
): Record<string, string> {
	return {
		authorization: `Basic ${Buffer.from(
			`${encodeURIComponent(clientId)}:${encodeURIComponent(secret)}`
		).toString('base64')}`
	};
}
