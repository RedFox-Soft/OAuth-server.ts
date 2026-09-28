import { member } from '../../helpers/_/object.js';

/*
 * The SQLSTATE of a failed statement, as Bun's PostgreSQL client reports it: in `errno`. Its `code`
 * is the client's own `ERR_POSTGRES_SERVER_ERROR` for every server error, so the classifiers that read
 * `code` never matched anything — a lost race for a bucket hostname answered 500 instead of "taken", and
 * two instances recording one new fault at once threw instead of merging. Found by
 * database/verify_postgres.ts against a real server; the in-memory suite cannot see it.
 */
export function sqlState(error: unknown): string | undefined {
	const state = member(error, 'errno');
	return typeof state === 'string' ? state : undefined;
}

const UNIQUE_VIOLATION = '23505';

export function isUniqueViolation(error: unknown): boolean {
	return sqlState(error) === UNIQUE_VIOLATION;
}
