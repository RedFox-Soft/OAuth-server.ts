import { Type as t, type Static } from '@sinclair/typebox';

/*
 * One taken right to email an account about a new sign-in (specs/138 data-model §4): the id says which (an account,
 * day, network and browser; or one of an account's five daily slots), and its existence is the claim. Written only by
 * an insert-if-absent, so two processes flushing the same sign-ins send one email between them.
 */
export const SignInAlertClaimPayload = t.Object({
	accountId: t.String(),
	exp: t.Number()
});

export type SignInAlertClaimPayload = Static<typeof SignInAlertClaimPayload>;
