import crypto from 'crypto';

/*
 * A password no one can type. The hash is of 32 random bytes discarded on the next line — deliberately not
 * a sentinel string, which would be a value someone could eventually guess, submit, or find in this source.
 * An account holding one acquires a usable password only through the self-service reset.
 *
 * Shared by the two ways an account comes to exist without a password: federation's just-in-time
 * provisioning and the end-user service's passwordless create.
 *
 * Hashed once per process, not once per account. An argon2 hash costs ~100 ms of CPU, and a directory's
 * initial SCIM import creates thousands of passwordless accounts at the 25 requests a second IPSIE asks a
 * server to sustain — 2.5 CPU-seconds a second spent hashing a value nobody will ever submit. Sharing the
 * hash gives nothing away that opens an account: its preimage is still discarded and never reaches storage
 * or a log, so nothing typed can match it. What a database reader learns is which accounts hold it — that
 * they have no usable password — and nothing more. A restart draws a fresh one.
 */
let shared: Promise<string> | undefined;

export function unusablePassword(): Promise<string> {
	shared ??= Bun.password
		.hash(crypto.randomBytes(32).toString('base64url'))
		.catch((error: unknown) => {
			shared = undefined;
			throw error;
		});
	return shared;
}
