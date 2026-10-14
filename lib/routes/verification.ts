import { Elysia, t } from 'elysia';
import {
	challengeLanguage,
	verifyLink,
	verifyCode,
	resend
} from '../verification/challenge.js';
import type { Language } from '../i18n/languages.js';
import { languageOfRequest } from '../i18n/request.js';
import { singleRange } from '../i18n/resolve.js';
import {
	verifySuccessPage,
	verifyFailurePage,
	codeEntryPage,
	resendAcceptedPage,
	verifyRateLimitedPage
} from '../interactions/verifyPages.js';
import { PLAIN_TEXTS } from '../i18n/texts/plain/index.js';

/*
 * These pages are opened from an email, often in another browser, so they speak the language the email was
 * written in unless the reader chose one here (specs/097). Read before the challenge is spent.
 */
async function pageLanguage(request: Request, id: string): Promise<Language> {
	return languageOfRequest(request, [singleRange(await challengeLanguage(id))])
		.language;
}

// Public, standalone verification endpoints. Deliberately NOT under the `ui/:uid/*`
// interaction-cookie guard: a verification link/code is used from an email, often in a
// different browser or session, so the challenge itself carries the account binding.
export const verificationRoutes = new Elysia({ name: 'verification' })
	.get(
		'/verify-email',
		async ({ query, request }) => {
			const language = await pageLanguage(request, query.token);
			const result = await verifyLink(query.token);
			return result.ok
				? verifySuccessPage(language)
				: verifyFailurePage(
						PLAIN_TEXTS[language].verify.messages.invalidLink,
						language
					);
		},
		{ query: t.Object({ token: t.String() }) }
	)
	.get(
		'/verify-email/code',
		async ({ query, request }) =>
			codeEntryPage(
				query.ref,
				undefined,
				await pageLanguage(request, query.ref)
			),
		{ query: t.Object({ ref: t.String() }) }
	)
	.post(
		'/verify-email/code',
		async ({ body, request }) => {
			const language = await pageLanguage(request, body.ref);
			const messages = PLAIN_TEXTS[language].verify.messages;
			const result = await verifyCode(body.ref, body.code);
			if (result.ok) return verifySuccessPage(language);
			if (result.reason === 'too_many') {
				return codeEntryPage(body.ref, messages.tooManyAttempts, language);
			}
			if (result.reason === 'invalid') {
				return verifyFailurePage(messages.invalidRequest, language);
			}
			return codeEntryPage(body.ref, messages.incorrectCode, language);
		},
		{ body: t.Object({ ref: t.String(), code: t.String() }) }
	)
	.post(
		'/verify-email/resend',
		async ({ body, set, request }) => {
			const language = await pageLanguage(request, body.ref);
			const messages = PLAIN_TEXTS[language].verify.messages;
			const result = await resend(body.ref);
			if (!result.ok) {
				return verifyRateLimitedPage(
					result.reason === 'cooldown' ? messages.cooldown : messages.dailyCap,
					language
				);
			}
			if (result.sent && result.method === 'code' && result.newRef) {
				set.headers['location'] = `/verify-email/code?ref=${encodeURIComponent(
					result.newRef
				)}`;
				set.status = 303;
				return;
			}
			return resendAcceptedPage(language);
		},
		{ body: t.Object({ ref: t.String() }) }
	);
