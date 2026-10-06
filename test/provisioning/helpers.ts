import { elysia } from 'lib/index.js';

/*
 * The admin API and the token endpoint as a console and a directory reach them: over HTTP, through the real
 * application, so authorization, validation, audit and the token endpoint's own client authentication all
 * run as they do in production.
 */

export interface Reply {
	status: number;
	json: Record<string, unknown> & { [key: string]: unknown };
}

async function read(response: Response): Promise<Reply> {
	const text = await response.text();
	let json: Record<string, unknown>;
	try {
		json = text ? JSON.parse(text) : {};
	} catch {
		json = { raw: text };
	}
	return { status: response.status, json };
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
