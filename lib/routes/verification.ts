import { Elysia, t } from 'elysia';
import { verifyLink, verifyCode, resend } from '../verification/challenge.js';
import {
	verifySuccessPage,
	verifyFailurePage,
	codeEntryPage,
	resendAcceptedPage,
	verifyRateLimitedPage
} from '../interactions/verifyPages.js';

const INVALID_LINK =
	'This verification link is invalid or has expired. Request a new verification email below.';

// Public, standalone verification endpoints. Deliberately NOT under the `ui/:uid/*`
// interaction-cookie guard: a verification link/code is used from an email, often in a
// different browser or session, so the challenge itself carries the account binding.
export const verificationRoutes = new Elysia({ name: 'verification' })
	.get(
		'/verify-email',
		async ({ query }) => {
			const result = await verifyLink(query.token);
			return result.ok ? verifySuccessPage() : verifyFailurePage(INVALID_LINK);
		},
		{ query: t.Object({ token: t.String() }) }
	)
	.get('/verify-email/code', ({ query }) => codeEntryPage(query.ref), {
		query: t.Object({ ref: t.String() })
	})
	.post(
		'/verify-email/code',
		async ({ body }) => {
			const result = await verifyCode(body.ref, body.code);
			if (result.ok) return verifySuccessPage();
			if (result.reason === 'too_many') {
				return codeEntryPage(
					body.ref,
					'Too many incorrect attempts. Request a new code below.'
				);
			}
			if (result.reason === 'invalid') {
				return verifyFailurePage(
					'This verification request is invalid or has expired. Request a new code below.'
				);
			}
			return codeEntryPage(body.ref, 'Incorrect code. Please try again.');
		},
		{ body: t.Object({ ref: t.String(), code: t.String() }) }
	)
	.post(
		'/verify-email/resend',
		async ({ body, set }) => {
			const result = await resend(body.ref);
			if (!result.ok) {
				return verifyRateLimitedPage(
					result.reason === 'cooldown'
						? 'Please wait a moment before requesting another verification email.'
						: 'You have requested too many verification emails today. Please try again later.'
				);
			}
			if (result.sent && result.method === 'code' && result.newRef) {
				set.headers['location'] = `/verify-email/code?ref=${encodeURIComponent(
					result.newRef
				)}`;
				set.status = 303;
				return;
			}
			return resendAcceptedPage();
		},
		{ body: t.Object({ ref: t.String() }) }
	);
