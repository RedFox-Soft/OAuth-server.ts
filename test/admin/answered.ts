import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { adminErrorBody } from 'lib/admin/auth/rbac.ts';

type AdminErrorBody = ReturnType<typeof adminErrorBody>;

/*
 * Every error body an admin route answers with: the shared one, and the one the client routes return
 * for client metadata they refuse (422).
 */
const ErrorBody = Type.Object({
	error: Type.String(),
	message: Type.String()
});

type Refusal = AdminErrorBody | Static<typeof ErrorBody>;

/*
 * Neither null nor an error body — the members of `data`'s type left once those are taken out. The
 * check below is what establishes it: both refusals match `ErrorBody`, and no answer does.
 */
function isAnswer<D>(data: D): data is Exclude<D, Refusal | null> {
	return data !== null && !Value.Check(ErrorBody, data);
}

/*
 * The body of an admin route that succeeded. Treaty types `data` as the route's return type joined with
 * the bodies the routes' `onError` returns, since Elysia counts an `onError` return as a response, and
 * as null when the call was refused. A test that expects success checks for both, and a refusal fails
 * here with its message instead of as a read of a member the error body does not have.
 */
export function answered<D>(data: D): Exclude<D, Refusal | null> {
	if (!isAnswer(data)) {
		throw new Error(
			Value.Check(ErrorBody, data)
				? `expected an admin answer, got an error: ${data.message}`
				: 'expected an admin answer, the call was refused'
		);
	}
	return data;
}
