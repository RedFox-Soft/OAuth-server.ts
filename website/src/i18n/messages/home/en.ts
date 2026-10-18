import { rich } from '../../types.ts';

/* The values a home-page sentence is built around; each is computed by the view, never written here. */
export interface HomeFacts {
	backends: string;
	tools: number;
}

export default {
	title: 'FoxAuth — the authorization server for the agent era',
	description:
		'One server for sign-in, APIs and AI agents: OAuth 2.1 and OpenID Connect, free on FoxAuth Cloud for up to 1,000,000 monthly active users.',
	hero: {
		eyebrow: 'OAuth 2.1 · OpenID Connect · MCP',
		heading: 'One server for your users, your APIs and your AI agents.',
		lead: 'Sign-in, enterprise identity providers, directory sync, banking-grade token security and authorization for AI agents: 30 standards that take a team years to build, already built and tested. Start free on FoxAuth Cloud with up to 1,000,000 monthly active users per project, or run it yourself.',
		getStarted: 'Run it yourself',
		freeAccount: 'Create a free account',
		github: 'View on GitHub',
		specifications: '30 specifications',
		freeUsers: '1,000,000 MAU free',
		quickstartCaption: 'Two commands and a browser tab',
		givesHeading: 'What those two commands give you',
		gives: [
			{
				head: 'A database',
				body: 'started and provisioned, with indexes and a signing key'
			},
			{
				head: 'Admin console',
				body: 'at /admin, with first-run setup for the super administrator'
			},
			{
				head: 'Discovery',
				body: 'at /.well-known/openid-configuration, reflecting the flags you set'
			},
			{
				head: 'No account',
				body: 'no account with us, no API key, no phone call'
			}
		]
	},
	console: {
		eyebrow: 'The console',
		heading: 'Everything an operator needs, without a second product.',
		lead: "Projects with their applications and APIs, end-users, upstream providers, SCIM connections, settings, SMTP, signing keys, monthly active users and an append-only audit trail, all in one console that you sign into through the server's own OpenID Connect flow, or through your organisation's identity provider. A change that could lock people out says whom it affects before it applies. The same API is what an AI agent uses over MCP.",
		screenshotAlt:
			'The FoxAuth admin console listing the applications (OAuth clients) of a project.',
		screenshotCaption:
			"A project's applications in the built-in console. Every change here is an audit entry."
	},
	audiences: {
		eyebrow: 'Who runs it',
		heading: 'Three teams, one server.',
		lead: 'The same binary, the same admin API. What changes, for the most part, is which flags you set.',
		seeAll: 'See all features',
		/* A point is a plain string unless it carries a computed value, in which case it is a function of the facts. */
		cards: [
			{
				title: 'For TypeScript teams',
				body: 'Bun and Elysia, one command to run, and 31 named seams you replace with your own function instead of forking.',
				points: [
					'Runs on Bun; the HTTP layer is Elysia',
					({ backends }: HomeFacts) =>
						`${backends} in production, in-memory for tests`,
					'31 override seams, resolved at call time'
				]
			},
			{
				title: 'For AI-agent builders',
				body: 'Protect your own MCP server with it, and let an agent administer the instance through the console’s own code path. There is no separate privileged API to keep in step.',
				points: [
					'Declare your MCP server; get audience-bound tokens (RFC 8707)',
					'Client ID Metadata Documents, so an agent host needs no setup',
					({ tools }: HomeFacts) =>
						`${tools} MCP tools for administration, off until you set mcp.enabled`
				]
			},
			{
				title: 'For regulated industries',
				body: 'The banking-grade profiles are implemented today, and none of them is waiting on a roadmap. Turn on the flag your regulator asks for.',
				points: [
					'FAPI, DPoP, PAR, mTLS, CIBA, RAR, JARM',
					'Append-only admin audit trail',
					'Per-identity brute-force throttle'
				]
			}
		]
	},
	quickStart: {
		eyebrow: 'Quick start',
		heading: 'A token in five minutes.',
		lead: 'No account with us, no API key. Three short pages, and you should have a token in your terminal.',
		steps: [
			{
				title: 'Run the server',
				body: 'Docker Compose starts the database, provisions the schema and seeds the admin console. One file per datastore; pick either.'
			},
			{
				title: 'Register a client',
				body: 'Create a project and its first OAuth client in the console, with exact redirect URIs.'
			},
			{
				title: 'Get a token',
				body: 'Walk the Authorization Code flow with PKCE and read the claims out of the ID token.'
			}
		]
	},
	standards: {
		eyebrow: 'Standards',
		heading: 'Thirty specifications, implemented.',
		lead: 'Every entry below is code in the repository, with tests. Each links to the spec it implements; the Reference names the flag that governs it.',
		reference: 'Endpoint reference'
	},
	mcp: {
		eyebrow: 'An OAuth server for MCP',
		heading: 'Protect your MCP server, and let an agent operate this one.',
		protect: rich(
			'Declare your own MCP server as a protected resource of a project and this server mints tokens whose audience is exactly that resource. No code here, no restart. An agent host discovers it, signs your users in, and comes back with a token your MCP server verifies against the published keys without asking anything. A ',
			{ code: 'client_id' },
			' that is an HTTPS URL is accepted as a client identity document, so a host with nothing to configure still connects.'
		),
		operate: (tools: number) =>
			rich(
				'Turn on ',
				{ code: 'mcp.enabled' },
				' and the management API is served to an AI agent at ',
				{ code: 'POST /mcp' },
				` as an OAuth 2.1 protected resource. Each of the ${tools} tools rebuilds the request the console would have sent and runs the console's own permission checks, validation and audit write, so no privileged back door can drift away from the console.`
			),
		confirm:
			'Destructive and instance-wide operations need two calls: the first returns a confirmation token, the second carries it. It is off by default.',
		protectButton: 'Protect your MCP server',
		allTools: (tools: number) => `All ${tools} MCP tools`
	},
	start: {
		eyebrow: 'Start',
		heading: 'Start free, today.',
		lead: 'Create a free account on FoxAuth Cloud, with up to 1,000,000 monthly active users per project, or run the server yourself this afternoon. Paid cloud plans are in development.',
		freeAccount: 'Create a free account',
		getStarted: 'Run it yourself',
		docs: 'Read the docs'
	}
};
