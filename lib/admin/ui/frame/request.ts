/*
 * The one way the console talks to the admin API.
 *
 * Every page used to carry its own `send`/`post`/`act` and some twenty inline `res.json().catch(...)`
 * reads, and they disagreed about what a refusal says: some passed the server's reason on, some replaced
 * it with "failed to …". One helper answers one shape, so a page decides what to show and never how to
 * read a response.
 *
 * It never throws on a non-2xx answer — a refusal is an outcome the page handles — and a 401 means the
 * session ended, so it sends the browser to sign in and back to where the operator was.
 */

export interface AdminErrorBody {
	error: string;
	message: string;
	field?: string;
	error_reference?: string;
	blockers?: unknown;
	failedAreas?: unknown;
	acknowledgementRequired?: unknown;
	conflicts?: unknown;
	confirmationRequired?: unknown;
	/* A plan's refusal (specs/102): shown as what the plan allows, never as a permission error. */
	code?: unknown;
	limit?: unknown;
	[key: string]: unknown;
}

export type RequestResult<T> =
	| { ok: true; status: number; data: T }
	| { ok: false; status: number; error: AdminErrorBody };

function isErrorBody(value: unknown): value is AdminErrorBody {
	return (
		typeof value === 'object' &&
		value !== null &&
		typeof (value as { message?: unknown }).message === 'string'
	);
}

function signInAgain(): void {
	const here = `${window.location.pathname}${window.location.search}`;
	window.location.assign(`/admin/login?next=${encodeURIComponent(here)}`);
}

export async function request<T = unknown>(
	method: string,
	url: string,
	body?: unknown
): Promise<RequestResult<T>> {
	let res: Response;
	try {
		res = await fetch(url, {
			method,
			headers:
				body === undefined ? undefined : { 'content-type': 'application/json' },
			body: body === undefined ? undefined : JSON.stringify(body)
		});
	} catch {
		return {
			ok: false,
			status: 0,
			error: {
				error: 'network',
				message:
					'The server could not be reached. Check the connection and try again.'
			}
		};
	}
	if (res.status === 401) {
		signInAgain();
	}
	const parsed: unknown = await res.json().catch(() => null);
	if (res.ok) {
		// The shape is the route's: the console reads what the admin API answers, typed at the call.
		return { ok: true, status: res.status, data: parsed as T };
	}
	const fallback = `The server refused the request (${String(res.status)}).`;
	/*
	 * A body without a `message` is still the server's answer — a 409 preview (an address change's, a move's)
	 * carries its whole content in other fields — so it is kept, with a generic sentence added for display.
	 */
	const error: AdminErrorBody = isErrorBody(parsed)
		? parsed
		: typeof parsed === 'object' && parsed !== null
			? {
					error: 'unknown',
					...(parsed as Record<string, unknown>),
					message: fallback
				}
			: { error: 'unknown', message: fallback };
	return { ok: false, status: res.status, error };
}
