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

/*
 * The body of an admin route that succeeded. Treaty types `data` as the route's return type joined with
 * the bodies the routes' `onError` returns, since Elysia counts an `onError` return as a response, and
 * as null when the call was refused. A test that expects success checks for both, and a refusal fails
 * here with its message instead of as a read of a member the error body does not have.
 */
export function answered<T>(
	data: T | AdminErrorBody | Static<typeof ErrorBody> | null
): T {
	if (data === null) {
		throw new Error('expected an admin answer, the call was refused');
	}
	if (Value.Check(ErrorBody, data)) {
		throw new Error(`expected an admin answer, got an error: ${data.message}`);
	}
	return data;
}
