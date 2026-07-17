import { adminSessionStore } from '../../adapters/index.js';
import {
	ADMIN_SESSION_COOKIE,
	ADMIN_SESSION_TTL_SECONDS,
	ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
} from '../consts.js';
import type { AdminSession } from '../../adapters/types.js';

export async function createAdminSession(data: {
	userId: string;
	bucketId: string;
	tokens: AdminSession['tokens'];
}) {
	return adminSessionStore.create({
		...data,
		ttlSeconds: ADMIN_SESSION_TTL_SECONDS,
		absoluteTtlSeconds: ADMIN_SESSION_ABSOLUTE_TTL_SECONDS
	});
}

export function sessionCookieAttributes() {
	return {
		httpOnly: true,
		sameSite: 'strict' as const,
		secure: true,
		path: '/admin',
		maxAge: ADMIN_SESSION_TTL_SECONDS
	};
}

export const SESSION_COOKIE_NAME = ADMIN_SESSION_COOKIE;
