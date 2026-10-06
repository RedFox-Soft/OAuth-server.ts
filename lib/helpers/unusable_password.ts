import crypto from 'crypto';

/*
 * A password no one can type. The hash is of 32 random bytes discarded on the next line — deliberately not
 * a sentinel string, which would be a value someone could eventually guess, submit, or find in this source.
 * An account holding one acquires a usable password only through the self-service reset.
 *
 * Shared by the two ways an account comes to exist without a password: federation's just-in-time
 * provisioning and the end-user service's passwordless create.
 */
export async function unusablePassword(): Promise<string> {
	return Bun.password.hash(crypto.randomBytes(32).toString('base64url'));
}
