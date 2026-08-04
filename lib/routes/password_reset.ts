import { Elysia, t } from 'elysia';

import { load, consume } from '../password_reset/challenge.js';
import {
	resetFormPage,
	resetSuccessPage,
	resetFailurePage
} from '../interactions/resetPages.js';

// Public, standalone reset endpoints. Deliberately NOT under the `ui/:uid/*` interaction-cookie guard: a
// reset link is opened from an email, often in a different browser or session, so the secret itself carries
// the account binding — the same reasoning lib/routes/verification.ts records for /verify-email.
export const passwordResetRoutes = new Elysia({ name: 'password-reset' })
	/*
	 * Renders the form and consumes nothing. Mail clients, security gateways and link-preview bots fetch
	 * URLs found in email; a GET that spent the secret would burn it before the user clicked.
	 */
	.get(
		'/reset-password',
		async ({ query }) => {
			const loaded = await load(query.token);
			return loaded.ok ? resetFormPage(query.token) : resetFailurePage();
		},
		{ query: t.Object({ token: t.String() }) }
	)
	.post(
		'/reset-password',
		async ({ body }) => {
			/*
			 * Checked here rather than in the engine, which is what keeps "a mismatch does not consume the
			 * secret" a property of the code rather than a rule someone has to remember: `consume` is never
			 * reached with a mismatched pair.
			 */
			if (body.password !== body.confirmPassword) {
				return resetFormPage(body.token, 'Those passwords do not match.');
			}

			const result = await consume(body.token, body.password);
			if (!result.ok) {
				return resetFailurePage();
			}

			return resetSuccessPage();
		},
		{
			body: t.Object({
				token: t.String(),
				password: t.String(),
				confirmPassword: t.String()
			})
		}
	);
