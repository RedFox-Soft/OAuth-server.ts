import { Elysia, t } from 'elysia';

import { load, consume } from '../password_reset/challenge.js';
import { END_USER_PASSWORD_MIN_LENGTH } from '../consts/password_policy.js';
import {
	resetFormPage,
	resetSuccessPage,
	resetFailurePage
} from '../interactions/resetPages.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';
import { passwordTooShort } from '../i18n/texts/signIn/index.js';
import type { Language } from '../i18n/languages.js';
import { languageOfRequest } from '../i18n/request.js';
import { singleRange } from '../i18n/resolve.js';

/*
 * A reset or invitation page speaks the language its email was written in, unless the reader chose one here
 * (specs/097). An unknown or spent link has no email to follow, so the browser decides.
 */
function pageLanguage(
	request: Request,
	loaded: Awaited<ReturnType<typeof load>>
): Language {
	return languageOfRequest(request, [
		singleRange(loaded.ok ? loaded.challenge.language : undefined)
	]).language;
}

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
		async ({ query, request }) => {
			const loaded = await load(query.token);
			const language = pageLanguage(request, loaded);
			return loaded.ok
				? resetFormPage(query.token, loaded, undefined, language)
				: resetFailurePage(language);
		},
		{ query: t.Object({ token: t.String() }) }
	)
	.post(
		'/reset-password',
		async ({ body, request }) => {
			/*
			 * Checked here rather than in the engine, which is what keeps "a mismatch does not consume the
			 * secret" a property of the code rather than a rule someone has to remember: `consume` is never
			 * reached with a mismatched pair. Loaded first only so the re-rendered form keeps its own words.
			 */
			const loaded = await load(body.token);
			const language = pageLanguage(request, loaded);
			const refused =
				body.password !== body.confirmPassword
					? PLAIN_TEXTS[language].reset.form.mismatch
					: body.password.length < END_USER_PASSWORD_MIN_LENGTH
						? passwordTooShort(language, END_USER_PASSWORD_MIN_LENGTH)
						: null;
			if (refused !== null) {
				return loaded.ok
					? resetFormPage(body.token, loaded, refused, language)
					: resetFailurePage(language);
			}

			const result = await consume(body.token, body.password);
			if (!result.ok) {
				return resetFailurePage(language);
			}

			return resetSuccessPage(result.purpose, language);
		},
		{
			body: t.Object({
				token: t.String(),
				password: t.String(),
				confirmPassword: t.String()
			})
		}
	);
