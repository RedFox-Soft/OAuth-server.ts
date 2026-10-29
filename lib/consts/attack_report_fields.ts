import type { ReportField } from './telemetry_fields.js';

/*
 * Everything an hourly attack report may carry (specs/114), declared once.
 *
 * The counting takes its type names and thresholds from here, the report builder emits only these fields,
 * the console card explains these entries and the site page is generated from them, so what an operator
 * reads and what leaves their server cannot drift apart.
 *
 * Import-free apart from a type, like every lib/consts/ declaration: the docs export, the console bundle and
 * the site read it without loading the server.
 */

/*
 * Fixed with the FoxTrust receiving spec and compiled into every release, with no override, by the same
 * owner decision as the usage report's destination (2026-10-28): an instance that never upgrades keeps
 * sending here, so the receiver may never move it.
 */
export const ATTACK_DESTINATION = 'https://api.foxtrust.dev/v1/foxauth/attacks';

/*
 * A change to a type's meaning or threshold, to a field, or to the address form is a new format, never an
 * edit of this one. Adding a probe label is not: the receiver accepts a label it does not know yet.
 */
export const ATTACK_REPORT_FORMAT = 1;

export const ATTACK_TYPE_NAMES = [
	'signin_failures',
	'client_auth_failures',
	'admin_credential_failures',
	'mail_requests',
	'flood',
	'probe'
] as const;

export type AttackTypeName = (typeof ATTACK_TYPE_NAMES)[number];

export interface AttackType {
	readonly name: AttackTypeName;
	/* Reported only once an address reaches this many in one hour, so an honest mistake never leaves. */
	readonly threshold: number;
	readonly meaning: string;
	readonly notCounted: string;
}

export const ATTACK_TYPES: readonly AttackType[] = [
	{
		name: 'signin_failures',
		threshold: 10,
		meaning:
			'A password or second-factor code refused at the sign-in page of any project, including a refusal because the page is throttling that account.',
		notCounted:
			'A sign-in refused after the password was right, for example a deactivated account.'
	},
	{
		name: 'client_auth_failures',
		threshold: 10,
		meaning:
			'A request to the token, introspection, revocation, pushed authorization, backchannel authentication or device authorization endpoint refused because the client secret, assertion or certificate it presented is wrong.',
		notCounted:
			'A request that presented no client credential at all, such as a public client sending only its client_id.'
	},
	{
		name: 'admin_credential_failures',
		threshold: 5,
		meaning:
			'A credential presented at a SCIM endpoint or at the MCP endpoint and refused as invalid.',
		notCounted:
			'A request without any credential, which is how an MCP client starts by protocol.'
	},
	{
		name: 'mail_requests',
		threshold: 10,
		meaning:
			'A request that asks the server to send an email to an address the caller names: a password reset, a self-service sign-up or a verification resend. Counted whatever the outcome, refused ones included.',
		notCounted: 'Email an administrator sends from the console.'
	},
	{
		name: 'flood',
		threshold: 20,
		meaning:
			'A request refused by the per-address rate limit because the caller sent too many.',
		notCounted:
			'Requests under the limit, and the per-connection limit of a SCIM connection.'
	},
	{
		name: 'probe',
		threshold: 1,
		meaning:
			'A request for one of the probe paths below: files and panels of other products that no FoxAuth server has, asked for only by scanners.',
		notCounted:
			'Any other path the server does not serve, such as a missing favicon.'
	}
];

export interface ProbePath {
	readonly label: string;
	readonly exact: readonly string[];
	readonly prefixes: readonly string[];
}

/*
 * Each entry is a file or panel of another product. Generic names a downstream application might serve beside
 * FoxAuth (/config.json, /admin.php, /backup.zip) are deliberately absent: a false probe report names an
 * honest visitor. Matched from the root of the host only, so a project addressed by a path segment is not
 * scanned for these; scanners walk the root, and a project's path is not something they can guess.
 */
export const PROBE_PATHS = [
	{
		label: 'dotenv',
		exact: [
			'/.env',
			'/.env.local',
			'/.env.production',
			'/.env.bak',
			'/.env.old',
			'/.env.backup'
		],
		prefixes: []
	},
	{ label: 'git', exact: ['/.git'], prefixes: ['/.git/'] },
	{
		label: 'wordpress',
		exact: ['/wp-login.php', '/xmlrpc.php', '/wp-config.php'],
		prefixes: ['/wp-admin', '/wp-content/', '/wp-includes/']
	},
	{
		label: 'php_admin',
		exact: ['/phpinfo.php'],
		prefixes: ['/phpmyadmin', '/phpMyAdmin']
	},
	{
		label: 'cloud_credentials',
		exact: ['/.aws/credentials', '/.docker/config.json', '/.dockercfg'],
		prefixes: []
	},
	{ label: 'ssh_keys', exact: [], prefixes: ['/.ssh/'] },
	{
		label: 'editor_config',
		exact: ['/.vscode/sftp.json', '/sftp-config.json'],
		prefixes: []
	},
	{ label: 'server_status', exact: ['/server-status'], prefixes: [] },
	{
		label: 'spring_actuator',
		exact: ['/actuator'],
		prefixes: ['/actuator/']
	},
	{ label: 'cgi', exact: [], prefixes: ['/cgi-bin/'] }
] as const satisfies readonly ProbePath[];

export type ProbeLabel = (typeof PROBE_PATHS)[number]['label'];

/* SC-006: a report stays small; the bound is a guard, since 500 entries of the largest shape fit well under it. */
export const ATTACK_MAX_ADDRESSES = 500;
export const ATTACK_REPORT_MAX_BYTES = 65_536;

/*
 * Per process and per hour. A hard cap rather than an LRU: under an address-rotation flood an LRU would evict
 * the heaviest early hitter, which is the address most worth reporting.
 */
export const ATTACK_MAX_TRACKED_ADDRESSES = 10_000;

/*
 * Quoted on the public page. It must equal what the FoxTrust receiving spec decides before the first release
 * that sends attack reports (specs/114 research R11).
 */
export const ATTACK_REPORT_RETENTION =
	'FoxTrust keeps each raw report for 30 days, then deletes it.';

export const ADDRESS_SOURCES_DOC =
	'automatic, direct, fly, cloudflare or listed';

export const ATTACK_REPORT_FIELDS: readonly ReportField[] = [
	{
		path: 'format',
		meaning: 'The version of this report format.',
		values: '1'
	},
	{
		path: 'instanceId',
		meaning:
			'The random identifier this server generated for itself, the same one its usage report carries. It says nothing about who runs the server.',
		values: 'a UUID'
	},
	{
		path: 'version',
		meaning: 'The FoxAuth release this server runs.',
		values: 'a version such as 1.4.0',
		absentWhen: 'the package manifest cannot be read'
	},
	{
		path: 'hour',
		meaning: 'The UTC hour the counts below were made in.',
		values: 'a time such as 2026-10-28T17:00:00.000Z'
	},
	{
		path: 'addressSource',
		meaning:
			'How the operator told the server it is reached. Only direct means no address can have come from a forwarded header.',
		values: ADDRESS_SOURCES_DOC
	},
	{
		path: 'addresses[].address',
		meaning:
			'An address that crossed a threshold in that hour. Only public internet addresses are ever sent.',
		values: 'an IPv4 address, or the /64 network of an IPv6 address'
	},
	{
		path: 'addresses[].counts.<type>',
		meaning:
			'How many times the address did that in the hour. A type appears only when its count reached the threshold.',
		values: `a whole number; types are ${ATTACK_TYPE_NAMES.join(', ')}`
	},
	{
		path: 'addresses[].probes',
		meaning: 'Which probe paths the address asked for, by label.',
		values: `labels from ${PROBE_PATHS.map((probe) => probe.label).join(', ')}`,
		absentWhen: 'the address asked for no probe path'
	},
	{
		path: 'omitted',
		meaning: `How many addresses crossed a threshold but did not fit; a report carries at most ${ATTACK_MAX_ADDRESSES}, those with the highest counts.`,
		values: 'a whole number, usually 0'
	}
];

/* Shown in the console before the first report. Documentation addresses only, which a real report never carries. */
export const EXAMPLE_ATTACK_REPORT = {
	format: ATTACK_REPORT_FORMAT,
	instanceId: '00000000-0000-4000-8000-000000000000',
	version: '1.4.0',
	hour: '2026-10-28T17:00:00.000Z',
	addressSource: 'automatic',
	addresses: [
		{ address: '192.0.2.44', counts: { signin_failures: 41 } },
		{
			address: '2001:db8:12:34::/64',
			counts: { probe: 2 },
			probes: ['dotenv', 'git']
		},
		{
			address: '198.51.100.20',
			counts: { client_auth_failures: 12, flood: 230 }
		}
	],
	omitted: 0
};
