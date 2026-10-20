import { useFeedback } from '../../frame/feedback.js';
import { useConfirm } from '../../frame/confirm.js';
import { request } from '../../frame/request.js';

/* The server's account of a change that can shut people out (specs/083 data-model §3). */
interface Preview {
	confirmationRequired: true;
	consequences: string[];
	expect: Record<string, number>;
}

function isPreview(body: unknown): body is Preview {
	return (
		typeof body === 'object' &&
		body !== null &&
		(body as { confirmationRequired?: unknown }).confirmationRequired ===
			true &&
		Array.isArray((body as { consequences?: unknown }).consequences)
	);
}

export type SignInSaveOutcome =
	| { kind: 'saved'; advisory?: string }
	| { kind: 'refused'; message: string }
	| { kind: 'failed' }
	| { kind: 'declined' };

/*
 * Saving a project's sign-in settings, wherever in the console it is done (the Sign-in tab, an application's "Who can
 * sign in"). Sent without consent first; a change that can shut people out is answered with the server's own account
 * of it, asked as a danger question, and sent again carrying the counts that were shown — so consent is always to the
 * numbers the operator read, and a count that moved in between is asked again.
 */
export function useSignInSave(bucketId: string, bucketName: string) {
	const feedback = useFeedback();
	const confirm = useConfirm();
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}`;

	return async function save(
		changes: Record<string, unknown>,
		consent?: Record<string, number>
	): Promise<SignInSaveOutcome> {
		const body: Record<string, unknown> = { ...changes };
		if (consent) {
			body.confirm = true;
			body.expect = consent;
		}
		const result = await request<{ advisory?: string }>('PATCH', base, body);
		if (result.ok) {
			feedback.done(`Sign-in of ${bucketName} saved.`);
			return { kind: 'saved', advisory: result.data.advisory };
		}
		if (result.status === 409 && isPreview(result.error)) {
			const preview = result.error;
			const agreed = await confirm('bucket.signIn.confirm', {
				target: bucketName,
				consequences: consent
					? [
							'What this change affects has changed since you last looked.',
							...preview.consequences
						]
					: preview.consequences
			});
			return agreed ? save(changes, preview.expect) : { kind: 'declined' };
		}
		if (result.status >= 500 || result.error.error_reference) {
			feedback.failed(result);
			return { kind: 'failed' };
		}
		return { kind: 'refused', message: result.error.message };
	};
}
