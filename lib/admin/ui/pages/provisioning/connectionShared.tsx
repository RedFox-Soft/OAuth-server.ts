import { Typography } from 'antd';
import type {
	ConnectionView,
	ConnectionWarning
} from '../../../../provisioning/service.js';

export type { ConnectionView, ConnectionWarning };

/*
 * Short and stated as the cause an administrator can act on, not as the server's code: each one is a reason
 * the directory's requests will be refused even though the connection looks configured.
 */
export const WARNING_LABELS: Record<ConnectionWarning, string> = {
	scim_disabled: 'SCIM is switched off in Settings',
	bucket_unaddressed: 'Bucket has no address yet',
	provider_disabled: 'Sign-in provider is disabled',
	client_credentials_disabled: 'Client-credentials grant is off',
	credential_kind_disabled: 'This credential kind is switched off'
};

export type CredentialKind = 'key' | 'secret' | 'static_token';

/* Which directory each credential suits, said where the kind is chosen. */
export const CREDENTIAL_KINDS: {
	kind: CredentialKind;
	label: string;
	suits: string;
}[] = [
	{
		kind: 'secret',
		label: 'Client secret',
		suits: 'For Microsoft Entra ID: choose "OAuth2 client credentials" there.'
	},
	{
		kind: 'static_token',
		label: 'Static token',
		suits: 'For Okta: sent in the Authorization header as a bearer token.'
	},
	{
		kind: 'key',
		label: 'Public key',
		suits: 'For a directory that signs client assertions (private_key_jwt).'
	}
];

export function connectionsApi(
	bucketId: string,
	connectionId?: string
): string {
	const base = `/admin/api/buckets/${encodeURIComponent(bucketId)}/provisioning-connections`;
	return connectionId === undefined
		? base
		: `${base}/${encodeURIComponent(connectionId)}`;
}

export function when(iso: string | Date | null | undefined): string {
	return iso ? new Date(iso).toLocaleString() : 'never';
}

/*
 * The guard's window, shown in the largest unit that states it exactly. The server takes seconds; an
 * administrator thinks in minutes, hours or days, so the picker offers those and the bounds are said in them.
 */
export const WINDOW_UNITS = [
	{ label: 'minutes', value: 60 },
	{ label: 'hours', value: 3600 },
	{ label: 'days', value: 86400 }
];
export const MIN_WINDOW_SECONDS = 300;
export const MAX_WINDOW_SECONDS = 604800;

export function windowParts(seconds: number): { amount: number; unit: number } {
	const unit =
		[...WINDOW_UNITS].reverse().find((u) => seconds % u.value === 0)?.value ??
		60;
	return { amount: seconds / unit, unit };
}

export function describeWindow(seconds: number): string {
	const { amount, unit } = windowParts(seconds);
	const label = WINDOW_UNITS.find((u) => u.value === unit)?.label ?? 'minutes';
	return `${amount} ${amount === 1 ? label.replace(/s$/, '') : label}`;
}

export type Threshold = { count: number; windowSeconds: number };

/*
 * Parsed here only to refuse what is not a key set before a round trip; whether the keys are public,
 * asymmetric and usable is the server's check, and its refusal is shown as is.
 */
export function parseJwks(text: string | undefined): {
	keys: Record<string, unknown>[];
} {
	const value: unknown = JSON.parse(text?.trim() || 'null');
	if (
		typeof value !== 'object' ||
		value === null ||
		!Array.isArray((value as { keys?: unknown }).keys)
	) {
		throw new TypeError('paste a JSON Web Key Set: {"keys":[…]}');
	}
	return value as { keys: Record<string, unknown>[] };
}

/* A value an administrator carries into somebody else's console, offered as one copy action. */
export function Copyable({ value }: { value: string | null }) {
	return value === null ? (
		<Typography.Text type="secondary">
			not available until the bucket has an address
		</Typography.Text>
	) : (
		<Typography.Text
			code
			copyable={{ text: value }}
		>
			{value}
		</Typography.Text>
	);
}

/*
 * What a directory administrator needs, as text to paste into a ticket or a chat — and never the secret,
 * which is shown once and copied on its own.
 */
export function setupDetails(c: ConnectionView): string {
	return [
		`SCIM base URL: ${c.scimBaseUrl ?? '(the bucket has no address yet)'}`,
		`Token endpoint: ${c.tokenEndpoint}`,
		`Client id: ${c.clientId}`,
		`Scope: ${c.scope}`
	].join('\n');
}

const people = (n: number, noun = 'user') =>
	`${n} ${noun}${n === 1 ? '' : 's'}`;
export { people };
