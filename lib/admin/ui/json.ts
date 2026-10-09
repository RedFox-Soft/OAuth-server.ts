/*
 * A response body from this server's own admin API, typed as the page expects it. `Response.json()` is
 * `any`; this states the shape once, at the read, as `` sql<Row[]>`…` `` does for a query whose shape the
 * query fixes — the route's response schema fixes this one.
 */
export async function readJson<T>(res: Response): Promise<T> {
	return (await res.json()) as T;
}
