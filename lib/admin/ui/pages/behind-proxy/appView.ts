import type { ProxyKind } from '../../../../behind_proxy/recipes.js';
import type {
	RuleView,
	WhoView
} from '../../../../behind_proxy/access_check.js';
import type { Who } from '../../../../behind_proxy/decide.js';

/* An app behind the operator's proxy, as `GET /admin/api/projects/:id/behind-proxy[/:appId]` answers it (specs/122). */
export interface AppView {
	id: string;
	name: string;
	address: string;
	proxyKind: ProxyKind;
	rules: RuleView[];
	verifyUrl: string;
	checklist: {
		createdAt: string;
		firstAskedAt: string | null;
		firstSignInAt: string | null;
		firstAllowedAt: string | null;
	};
	lastAskedAt: string | null;
	mismatchedHosts: string[];
	signUpsOpen: boolean;
}

export function behindProxyApi(bucketId: string, appId?: string): string {
	const base = `/admin/api/projects/${encodeURIComponent(bucketId)}/behind-proxy`;
	return appId === undefined ? base : `${base}/${encodeURIComponent(appId)}`;
}

export const PROXY_LABELS: Readonly<Record<ProxyKind, string>> = {
	caddy: 'Caddy',
	traefik: 'Traefik',
	nginx: 'nginx'
};

/* The app's host, as a person reads it: `grafana.example.com`, with a port only when it has one. */
export function hostOfAddress(address: string): string {
	try {
		return new URL(address).host;
	} catch {
		return address;
	}
}

/* A rule's path in words: a non-public rule covers everything under it, a public one only itself unless it says so. */
export function pathText(
	path: string,
	who: Pick<WhoView, 'kind'> & { subtree?: boolean }
): string {
	if (path === '/') return '/ (everything)';
	if (who.kind === 'public') {
		return who.subtree ? `${path} and below` : path;
	}
	return `${path} and below`;
}

/* Who a rule lets in, in one line. Group names come from the caller, which knows the current ones. */
export function whoText(
	who: Who | WhoView | null,
	nameOf: (id: string) => string | null
): string {
	if (!who) return 'No one';
	switch (who.kind) {
		case 'groups': {
			const names =
				'groupIds' in who
					? who.groupIds.map((id) => nameOf(id) ?? 'Deleted group')
					: who.groups.map((g) => g.name ?? 'Deleted group');
			return `Members of ${names.length > 0 ? names.join(', ') : 'no group'}`;
		}
		case 'project':
			return 'Everyone in the project';
		case 'public':
			return who.subtree
				? 'Anyone, no sign-in (and everything under it)'
				: 'Anyone, no sign-in';
		case 'none':
			return 'No one';
	}
}

/* When something happened, in words read at a glance. The record is written to the minute, so no finer. */
export function whenText(iso: string | null, now: number = Date.now()): string {
	if (!iso) return 'Never';
	const at = Date.parse(iso);
	const seconds = Math.max(0, (now - at) / 1000);
	if (seconds < 120) return 'just now';
	const minutes = Math.floor(seconds / 60);
	if (minutes < 60) return `${String(minutes)} minutes ago`;
	const hours = Math.floor(minutes / 60);
	if (hours < 48) return `${String(hours)} hours ago`;
	return new Date(at).toISOString().slice(0, 10);
}
