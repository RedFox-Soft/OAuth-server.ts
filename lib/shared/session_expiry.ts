import { ApplicationConfig as config } from 'lib/configs/application.js';
import { Session } from 'lib/models/session.js';
import type { SessionExpiryInput } from 'lib/models/id_token.js';

/*
 * What an ID token's `session_expiry` is computed from (IPSIE SL1 §3.2.1): the operator's bound, and the
 * end of the browser session the artefact names while that session still lives. The session's `exp`
 * already carries an upstream provider's own `session_expiry` (Session.save caps it), so this one read
 * covers both. Gathered here because the bound is a setting and the model graph reads none; the value
 * itself is computed where `iat` is decided, in IdToken.issue.
 */
export async function sessionExpiryInput(
	sessionUid: string | undefined
): Promise<SessionExpiryInput> {
	const session = sessionUid ? await Session.findByUid(sessionUid) : undefined;
	return {
		lifetime: config['idToken.relyingPartySessionLifetime'],
		sessionEnd: session?.payload.exp
	};
}
