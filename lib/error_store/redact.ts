import { createHmac, randomBytes } from 'node:crypto';

import { errorOriginSaltStore } from '../adapters/index.js';
import type { ErrorRecord, OriginCaptureLevel } from '../adapters/types.js';
import { truncate } from './fingerprint.js';

const USER_AGENT_LIMIT = 200;

/*
 * What a record may hold from a request, built as a whitelist.
 *
 * A whitelist rather than a blacklist of forbidden fields, and that is the whole design: a blacklist
 * fails the first time a new header or body field appears, and it fails silently, in a store nobody
 * reads until an incident. Nothing here copies a request and removes the sensitive parts — it names
 * what is taken, and everything unnamed is absent by construction.
 *
 * Consequently there is no path by which a client secret, a password, an access, refresh or identity
 * token, an authorization or DPoP header, or a cookie reaches storage. Where knowing *what* was
 * submitted matters, only field names are kept, the same rule and the same wording as
 * AdminAuditEntry.attributes.
 */
export interface CaptureSubject {
	clientId?: string | null;
	actor?: { id: string; email: string } | null;
	scope?: string | null;
	requestId?: string | null;
	/* Names only — never values. */
	submittedFields?: string[];
	headers: Headers;
}

/*
 * Resolved once per process and cached. A miss provisions one, which is safe to race: `create` writes
 * only when the store is empty, and its return value is the winner, so two instances starting together
 * converge on the same key rather than each installing its own.
 */
let saltPromise: Promise<Buffer> | undefined;

function resolveSalt(): Promise<Buffer> {
	saltPromise ??= (async () => {
		const existing = await errorOriginSaltStore.read();
		if (Buffer.isBuffer(existing) && existing.length === 32) {
			return existing;
		}
		const created = await errorOriginSaltStore.create(randomBytes(32));
		return Buffer.isBuffer(created) ? created : randomBytes(32);
	})();
	return saltPromise;
}

/* Test seam: forget the cached key so a spec can observe resolution again. */
export function resetOriginSalt(): void {
	saltPromise = undefined;
}

/*
 * The caller's address as the deployment allows it to be kept.
 *
 * `omitted` returns the explicit not-captured marker rather than null: a reader must be able to tell
 * "the operator chose not to look" from "there was nothing to see", without consulting the
 * configuration that was in force when the record was written.
 */
export async function captureOrigin(
	headers: Headers,
	level: OriginCaptureLevel
): Promise<string | null | 'not-captured'> {
	if (level === 'omitted') {
		return 'not-captured';
	}

	/*
	 * First hop of X-Forwarded-For, falling back to X-Real-IP. Both are client-supplied and therefore
	 * spoofable; that is acceptable for a diagnostic record and would not be for an access decision,
	 * which is why nothing authorizes on this value.
	 */
	const forwarded = headers.get('x-forwarded-for')?.split(',')[0]?.trim();
	const address = forwarded || headers.get('x-real-ip')?.trim() || '';
	if (!address) {
		return null;
	}
	if (level === 'full') {
		return truncate(address, 64);
	}

	const salt = await resolveSalt();
	// Keyed, and truncated to 16 hex characters: enough that two origins do not collide in a
	// four-figure store, not enough to be worth a rainbow table even if the key ever leaked.
	return createHmac('sha256', salt).update(address).digest('hex').slice(0, 16);
}

export async function buildRecord(
	subject: CaptureSubject,
	reference: string,
	level: OriginCaptureLevel,
	at: Date = new Date()
): Promise<ErrorRecord> {
	return {
		reference,
		at,
		/*
		 * Absent context is written as null rather than inferred. An unauthenticated malformed request
		 * genuinely has no client, and guessing one would make the record lie about who was involved —
		 * which is worse than a record that admits what it does not know.
		 */
		clientId: subject.clientId ?? null,
		actor: subject.actor ?? null,
		scope: subject.scope ?? null,
		requestId: subject.requestId ?? null,
		origin: await captureOrigin(subject.headers, level),
		userAgent:
			truncate(subject.headers.get('user-agent') ?? '', USER_AGENT_LIMIT) ||
			null,
		submittedFields: [...(subject.submittedFields ?? [])].sort()
	};
}

/*
 * Field *names* from a parsed body or query, for the one question a record must be able to answer
 * without keeping values: what did the request carry?
 *
 * Takes an already-parsed object, so nothing here reads a raw body — and returns names only, so
 * passing it a body full of secrets is safe by construction rather than by care at the call site.
 */
export function fieldNamesOf(source: unknown): string[] {
	if (!source || typeof source !== 'object') {
		return [];
	}
	return Object.keys(source as Record<string, unknown>).sort();
}
