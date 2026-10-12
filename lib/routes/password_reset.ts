import { Elysia, t } from 'elysia';

import { load, consume } from '../password_reset/challenge.js';
import {
	END_USER_PASSWORD_MIN_LENGTH,
	END_USER_PASSWORD_TOO_SHORT
} from '../consts/password_policy.js';
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
			return loaded.ok
				? resetFormPage(query.token, loaded)
				: resetFailurePage();
		},
		{ query: t.Object({ token: t.String() }) }
	)
	.post(
		'/reset-password',
		async ({ body }) => {
			/*
			 * Checked here rather than in the engine, which is what keeps "a mismatch does not consume the
			 * secret" a property of the code rather than a rule someone has to remember: `consume` is never
			 * reached with a mismatched pair. Loaded first only so the re-rendered form keeps its own words.
			 */
			const refused =
				body.password !== body.confirmPassword
					? 'Those passwords do not match.'
					: body.password.length < END_USER_PASSWORD_MIN_LENGTH
						? END_USER_PASSWORD_TOO_SHORT
						: null;
			if (refused !== null) {
				const loaded = await load(body.token);
				return loaded.ok
					? resetFormPage(body.token, loaded, refused)
					: resetFailurePage();
			}

			const result = await consume(body.token, body.password);
			if (!result.ok) {
				return resetFailurePage();
			}

			return resetSuccessPage(result.purpose);
		},
		{
			body: t.Object({
				token: t.String(),
				password: t.String(),
				confirmPassword: t.String()
			})
		}
	);
