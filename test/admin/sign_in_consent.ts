import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';

/* What a bucket change that tightens sign-in answers before it is applied (specs/083). */
export const SignInPreview = Type.Object({
	confirmationRequired: Type.Literal(true),
	consequences: Type.Array(Type.String()),
	expect: Type.Record(Type.String(), Type.Number()),
	changes: Type.Array(Type.String())
});
export type SignInPreview = Static<typeof SignInPreview>;

export interface Consent {
	confirm?: true;
	expect?: Record<string, number>;
}

/* The body of a 409, wherever the client keeps it: Eden's `error.value`, or a plain `body`. */
function bodyOf(answer: object): unknown {
	if ('error' in answer) {
		const error: unknown = answer.error;
		if (error !== null && typeof error === 'object' && 'value' in error) {
			return error.value;
		}
	}
	return 'body' in answer ? answer.body : undefined;
}

/*
 * A sign-in change made as the console makes it: sent, and when the server answers with a preview,
 * repeated with consent to the counts the preview showed. Any other answer — success, or a refusal that
 * offers no preview — is returned as it came, so a test still sees the refusal it is about.
 */
export async function consenting<R extends { status: number }>(
	send: (consent: Consent) => Promise<R>
): Promise<R> {
	const first = await send({});
	if (first.status !== 409) return first;
	const preview = bodyOf(first);
	if (!Value.Check(SignInPreview, preview)) return first;
	return send({ confirm: true, expect: preview.expect });
}
