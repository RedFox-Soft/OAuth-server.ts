/*
 * Bound a promise that has no bound of its own.
 *
 * Written for the storage reachability probe, where the failure it addresses is specific: a driver's
 * timeout covers *establishing* a connection, not a query issued on one it already holds. A database
 * that is up, connected and no longer answering is the ordinary shape of a database in trouble, and
 * against a paused PostgreSQL container an unbounded probe took 30 seconds to come back — three
 * orchestrator probe intervals spent holding one request open.
 *
 * Its own file, and free of imports, so the two things that matter about it can be tested in
 * milliseconds without a datastore: that it rejects on time, and that it does not leave a timer
 * behind when the work wins the race. A pending timer here would keep the process alive past the
 * work it was guarding.
 *
 * What it cannot do is cancel the losing work — a query already sent finishes into nothing. Callers
 * that might issue another one meanwhile have to say so themselves; `lib/actions/ready.ts` shares a
 * single outstanding probe for exactly that reason.
 */
export async function withDeadline<T>(
	work: Promise<T>,
	timeoutMs: number,
	subject: string
): Promise<T> {
	let expire: ReturnType<typeof setTimeout> | undefined;

	const deadline = new Promise<never>((_resolve, reject) => {
		expire = setTimeout(
			() =>
				reject(new Error(`${subject} did not answer within ${timeoutMs}ms`)),
			timeoutMs
		);
	});

	try {
		return await Promise.race([work, deadline]);
	} finally {
		clearTimeout(expire);
	}
}
