import { t } from 'elysia';

/*
 * Returned in place of the stored credential, and accepted back on PUT to mean "leave it unchanged",
 * so the console never has to hold the real value in order to save the rest of the card.
 */
export const SENTRY_DSN_MASK = '********';

/*
 * Two fields, and that is the whole surface.
 *
 * No `environment` or `release`: both are resolved from the deployment (NODE_ENV, the package
 * version), so accepting them would let the console and the deployment disagree about which build an
 * alert came from — with the console winning, which is the wrong way round.
 *
 * No `queueDepth` either: the outbound bound is a constant in sentry/dispatch.ts, which records why
 * it is not an operator's decision.
 */
export const UpdateSentryBody = t.Object({
	enabled: t.Boolean(),
	dsn: t.String()
});
