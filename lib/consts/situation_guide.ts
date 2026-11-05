import type { SituationId } from '../admin/ui/pages/applications/situations.js';

/*
 * The situation guide ("What do you need?"), declared once. The console reads it to draw the guide and to decide what
 * each answer's button does; the docs export reads it to publish the same list on the site. Plain data and import-free
 * at runtime for that reason: a type import only, so a script can load it without reaching the model graph.
 *
 * A situation is a console preset or a console address, never an API field: the server never learns which one was
 * chosen. What an application situation fills in lives in `lib/admin/ui/pages/applications/situations.ts`; `preset`
 * names it rather than repeating it.
 */

export type GuideTab = 'product' | 'enterprise';
export type GuideActor = 'person' | 'program' | 'agent';

/* An instance switch an answer needs. The settings keys are in GUIDE_FLAG_SETTINGS. */
export type GuideFlag =
	| 'deviceFlow'
	| 'clientCredentials'
	| 'federation'
	| 'scim'
	| 'tokenExchange'
	| 'jwtBearer'
	| 'ciba'
	| 'mcp'
	| 'rpInitiatedLogout'
	| 'registration'
	| 'richAuthorizationRequests'
	| 'dpop'
	| 'ipsieSl1'
	| 'clientIdMetadataDocument'
	| 'plans';

/* The ApplicationConfig key each switch is read from. */
export const GUIDE_FLAG_SETTINGS: Readonly<Record<GuideFlag, string>> = {
	deviceFlow: 'deviceFlow.enabled',
	clientCredentials: 'clientCredentials.enabled',
	federation: 'federation.enabled',
	scim: 'scim.enabled',
	tokenExchange: 'tokenExchange.enabled',
	jwtBearer: 'jwtBearer.enabled',
	ciba: 'ciba.enabled',
	mcp: 'mcp.enabled',
	rpInitiatedLogout: 'rpInitiatedLogout.enabled',
	registration: 'registration.enabled',
	richAuthorizationRequests: 'richAuthorizationRequests.enabled',
	dpop: 'dpop.enabled',
	ipsieSl1: 'ipsieSl1.enabled',
	clientIdMetadataDocument: 'clientIdMetadataDocument.enabled',
	plans: 'plans.enabled'
};

/*
 * The Settings pane each switch is on, so "Open the setting" lands where it can be switched. The pane ids are the
 * settings catalog's domains (lib/admin/settings/catalog.ts SETTING_DOMAINS), written out because this module imports
 * nothing; test/situation_guide/availability.spec.ts holds each one to the catalog.
 */
export type GuideSettingsPane =
	| 'grants'
	| 'request-security'
	| 'endpoints'
	| 'signin-abuse'
	| 'diagnostics'
	| 'integrations'
	| 'plans';

export const GUIDE_FLAG_PANES: Readonly<Record<GuideFlag, GuideSettingsPane>> =
	{
		deviceFlow: 'grants',
		clientCredentials: 'grants',
		federation: 'signin-abuse',
		scim: 'integrations',
		tokenExchange: 'grants',
		jwtBearer: 'grants',
		ciba: 'grants',
		mcp: 'integrations',
		rpInitiatedLogout: 'endpoints',
		registration: 'endpoints',
		richAuthorizationRequests: 'request-security',
		dpop: 'request-security',
		ipsieSl1: 'request-security',
		clientIdMetadataDocument: 'endpoints',
		plans: 'plans'
	};

/* `changeAddress` is the project's own `can.changeAddress`: narrower than `edit` (lib/admin/auth/can.ts). */
export type GuideRole = 'edit' | 'manageUsers' | 'changeAddress' | 'super';

/* What a project's plan counts against a limit; adding one more needs room under it. */
export type GuideRoom = 'applications' | 'apis' | 'connectedServices';

export type GuideTarget =
	/* A project tab: the BucketTab segment, for example 'applications'. */
	| { area: string; query?: Record<string, string> }
	| { instance: 'settings'; pane?: string }
	| { instance: 'administrators'; area?: string }
	/* A console section of the whole instance that every administrator may open. */
	| { section: 'teams' | 'audit' }
	/* A page the project itself serves to its people, at its own issuer; it opens in a new tab. */
	| { projectPage: 'account/apps' }
	/* A foxauth.dev path. */
	| { docs: string };

/* The drawing a lane is shown as. The drawings are in lib/situation_guide/parts.ts. */
export type GuidePart =
	| 'person'
	| 'laptop'
	| 'browser'
	| 'server'
	| 'phone'
	| 'tv'
	| 'clock'
	| 'agent'
	| 'api'
	| 'company'
	| 'directory'
	| 'fox'
	| 'cloud'
	| 'mail'
	| 'authenticator'
	| 'globe'
	| 'team'
	| 'audit'
	| 'thief'
	| 'proxy';

export interface GuideLane {
	id: string;
	label: string;
	/*
	 * The diagram's colours read this; `part` is the drawing. `proxy` is the reader's own reverse proxy, the gate every
	 * request to an app behind it passes through: drawn apart so a picture never shows FoxAuth on that path.
	 */
	kind:
		| 'person'
		| 'browser'
		| 'app'
		| 'api'
		| 'fox'
		| 'agent'
		| 'outside'
		| 'company'
		| 'proxy';
	part: GuidePart;
}

/* What is wrong without FoxAuth, drawn as a mark on the part that has the problem. */
export type ProblemMark = 'password' | 'secret' | 'open' | 'copy' | 'missing';

/* The names the drawn screens use, said once so the site and the console show the same example. */
export const GUIDE_EXAMPLES = {
	app: 'Acme Notes',
	company: 'Acme Corp',
	agent: 'Claude',
	service: 'Google'
} as const;

export interface GuideStep {
	from: string;
	to: string;
	label: string;
	text: string;
	style?: 'request' | 'redirect' | 'token' | 'refusal';
}

export interface GuidePreview {
	/*
	 * `companySignIn` is a sign-in page with a button for the company (GUIDE_EXAMPLES.company); `agentConsent` a
	 * consent page that names the agent (GUIDE_EXAMPLES.agent) and what it may do in the app; `adminConsent` the same
	 * for the agent acting in FoxAuth's own console; `serviceConsent` the page that connects the person's account at
	 * an outside service (GUIDE_EXAMPLES.service) to the app; `signUp` the form that creates an account.
	 */
	kind:
		| 'signIn'
		| 'signUp'
		| 'companySignIn'
		| 'consent'
		| 'agentConsent'
		| 'adminConsent'
		| 'serviceConsent'
		| 'deviceCode'
		| 'approve'
		| 'none';
	lines: string[];
}

export interface GuideSituation {
	id: string;
	tab: GuideTab;
	/* Its place in the two questions. Absent: a chip (product) or a list item (enterprise). */
	ask?: { actor: GuideActor; answer: string };
	title: string;
	sentence: string;
	protocol: string;
	lanes: GuideLane[];
	steps: GuideStep[];
	/* The first picture: the lane with the problem, its mark, and about six plain words. */
	problem: {
		at: LaneId;
		mark: ProblemMark;
		caption: string;
		/*
		 * The lanes the problem picture draws, where the rule in lib/situation_guide/scene.ts would draw a part of
		 * the fix or leave out the party the caption is about.
		 */
		lanes?: LaneId[];
	};
	/* The second picture's words: what FoxAuth changes, as plainly. */
	fixCaption: string;
	/* The situation that usually comes next, on the same tab. */
	next?: string;
	sees: GuidePreview;
	/* For an application situation, the console preset it applies. */
	preset?: SituationId;
	needs: {
		flags?: GuideFlag[];
		/* Switches of which any one is enough: the answer is switched off only when every one of them is. */
		anyOf?: GuideFlag[];
		planFeature?: 'enterpriseSignIn' | 'customSlug' | 'customDomain';
		/* The plan limit the button's form adds one more to. */
		room?: GuideRoom;
		role?: GuideRole;
	};
	action:
		| { kind: 'form'; target: GuideTarget }
		| { kind: 'open'; label: string; target: GuideTarget };
	goodToKnow: string[];
	/* Placeholders allowed: {issuer}, {discovery}, {console}. */
	prompt: string;
	/* Enterprise: listed first, with the hint that these usually come together. */
	first?: boolean;
}

export interface GuideQuestion {
	actor: GuideActor;
	title: string;
	sub: string;
	second: string;
	answers: readonly { answer: string; title: string; sub: string }[];
}

export const GUIDE_QUESTIONS: readonly GuideQuestion[] = [
	{
		actor: 'person',
		title: 'A person',
		sub: 'signs in to your app',
		second: 'Where does your code run?',
		answers: [
			{
				answer: 'server',
				title: 'On a server',
				sub: 'Next.js, Django, Rails, Laravel'
			},
			{
				answer: 'spa',
				title: 'In the browser',
				sub: 'React, Vue, Angular, no server'
			},
			{
				answer: 'native',
				title: 'Phone, desktop or terminal',
				sub: 'iOS, Android, Electron, CLI'
			},
			{
				answer: 'device',
				title: 'A device with no keyboard',
				sub: 'a TV, a set-top box, a kiosk'
			}
		]
	},
	{
		actor: 'program',
		title: 'A program with no person',
		sub: 'a service, a scheduled job, your API',
		second: 'What are you building?',
		answers: [
			{
				answer: 'service',
				title: 'A program that calls an API',
				sub: 'a background job, cron, another service'
			},
			{
				answer: 'api',
				title: 'An API to protect',
				sub: 'only your apps may call it'
			},
			{
				answer: 'platform',
				title: 'A platform for other developers',
				sub: 'they register their own apps'
			}
		]
	},
	{
		actor: 'agent',
		title: 'An AI agent',
		sub: 'Claude, Cursor, ChatGPT or your own',
		second: 'What does the agent need?',
		answers: [
			{
				answer: 'mcp',
				title: 'To connect to my MCP server',
				sub: 'after a person signs in, no registration'
			},
			{
				answer: 'connected',
				title: 'To use the person’s Google, GitHub…',
				sub: 'on their behalf, with their consent'
			},
			{
				answer: 'adminmcp',
				title: 'To manage FoxAuth itself',
				sub: 'through the administrative MCP'
			}
		]
	}
];

/*
 * The lanes of every diagram, declared once so the same box looks the same in every situation. `fox` is always the
 * accent and `outside` is a service the reader does not control.
 */
const LANES = {
	person: { label: 'Person', kind: 'person', part: 'person' },
	server: { label: 'Your server', kind: 'app', part: 'server' },
	spa: { label: 'Your browser app', kind: 'browser', part: 'browser' },
	app: { label: 'Your app', kind: 'app', part: 'laptop' },
	webapp: { label: 'Your app', kind: 'browser', part: 'browser' },
	fox: { label: 'FoxAuth', kind: 'fox', part: 'fox' },
	api: { label: 'Your API', kind: 'api', part: 'api' },
	otherapi: { label: 'Another API', kind: 'outside', part: 'api' },
	tv: { label: 'TV or device', kind: 'app', part: 'tv' },
	phone: { label: 'Person’s phone', kind: 'app', part: 'phone' },
	job: { label: 'Your program', kind: 'app', part: 'clock' },
	agent: { label: 'AI agent', kind: 'agent', part: 'agent' },
	mcp: { label: 'Your MCP server', kind: 'api', part: 'api' },
	google: { label: 'Google, GitHub, Slack', kind: 'outside', part: 'cloud' },
	googleOnly: { label: 'Google', kind: 'outside', part: 'cloud' },
	you: { label: 'You', kind: 'person', part: 'person' },
	mail: { label: 'Inbox', kind: 'outside', part: 'mail' },
	totp: { label: 'Authenticator app', kind: 'outside', part: 'authenticator' },
	domain: { label: 'Your address', kind: 'browser', part: 'globe' },
	idp: { label: 'Okta or Entra ID', kind: 'company', part: 'company' },
	dir: { label: 'Company directory', kind: 'company', part: 'directory' },
	employee: { label: 'Employee', kind: 'person', part: 'person' },
	apps: { label: 'Your apps', kind: 'browser', part: 'browser' },
	operator: { label: 'Call centre system', kind: 'app', part: 'laptop' },
	client: { label: 'Customer’s phone', kind: 'person', part: 'phone' },
	team: { label: 'Team', kind: 'person', part: 'team' },
	project: { label: 'Project', kind: 'fox', part: 'fox' },
	audit: { label: 'Audit trail', kind: 'fox', part: 'audit' },
	tool: { label: 'Internal tool', kind: 'browser', part: 'browser' },
	admin: { label: 'Administrator', kind: 'person', part: 'person' },
	itadmin: { label: 'Company IT', kind: 'company', part: 'company' },
	security: { label: 'Security team', kind: 'person', part: 'team' },
	dev: { label: 'Another developer’s app', kind: 'outside', part: 'laptop' },
	thief: { label: 'Someone with a copy', kind: 'outside', part: 'thief' },
	browser: { label: 'Person’s browser', kind: 'person', part: 'browser' },
	proxy: { label: 'Your proxy', kind: 'proxy', part: 'proxy' },
	proxied: { label: 'Your app', kind: 'api', part: 'server' }
} as const satisfies Record<string, Omit<GuideLane, 'id'>>;

export type LaneId = keyof typeof LANES;

function lanes(...ids: LaneId[]): GuideLane[] {
	return ids.map((id) => ({ id, ...LANES[id] }));
}

function step(
	from: LaneId,
	to: LaneId,
	label: string,
	text: string,
	style?: GuideStep['style']
): GuideStep {
	return { from, to, label, text, ...(style ? { style } : {}) };
}

/*
 * What an agent is asked: the task, the issuer and discovery address it works from, and how to do the console part.
 * Without the administrative MCP connected the agent asks the person to press the button; with it, it names the tool.
 */
function prompt(task: string, tool?: string, extra?: string): string {
	return [
		task,
		'The server’s issuer is {issuer} and its discovery document is {discovery}.',
		tool
			? `If the FoxAuth administrative MCP is connected, use ${tool}. Otherwise ask me to press the button for this in the console at {console}.`
			: 'Ask me to press the button for this in the console at {console}.',
		...(extra ? [extra] : [])
	].join('\n');
}

export const GUIDE_SITUATIONS: readonly GuideSituation[] = [
	/* Your product: the two questions */
	{
		id: 'server',
		tab: 'product',
		ask: { actor: 'person', answer: 'server' },
		title: 'A website with its own server',
		sentence:
			'Your server keeps a secret and trades a one-time code for tokens, so this is the simplest and the safest sign-in.',
		protocol:
			'OpenID Connect · Authorization Code + PKCE · client_secret_basic · refresh tokens',
		lanes: lanes('person', 'server', 'fox'),
		steps: [
			step(
				'person',
				'server',
				'Clicks “Sign in”',
				'The person clicks “Sign in” on your site.'
			),
			step(
				'server',
				'fox',
				'Sends to sign-in',
				'Your server sends the browser to the FoxAuth sign-in page.',
				'redirect'
			),
			step(
				'person',
				'fox',
				'Signs in',
				'The person types a password or uses Google. Only FoxAuth sees the password.'
			),
			step(
				'fox',
				'server',
				'One-time code',
				'FoxAuth sends the person back to your callback address with a one-time code.',
				'redirect'
			),
			step(
				'server',
				'fox',
				'Code + secret',
				'Your server trades the code for tokens and shows its secret. The browser never sees this.',
				'token'
			),
			step(
				'server',
				'person',
				'Signed in',
				'Your server starts a session, and the person is in.'
			)
		],
		problem: {
			at: 'server',
			mark: 'password',
			caption: 'Your server stores everyone’s passwords.'
		},
		fixCaption: 'Only FoxAuth ever sees the password.',
		sees: {
			kind: 'signIn',
			lines: [
				'The FoxAuth sign-in page',
				'Password, or a provider button',
				'Then back to your site, signed in'
			]
		},
		preset: 'server',
		needs: { room: 'applications', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'server' } }
		},
		goodToKnow: [
			'Plain http is allowed only for localhost. Every other address needs https.',
			'Keep the secret on the server, in an environment variable, never in the code.'
		],
		prompt: prompt(
			'Add sign-in through FoxAuth to my web app with a server (work out the stack from the code).\nFlow: Authorization Code + PKCE, a confidential application (client_secret_basic), refresh tokens.\nCallback: http://localhost:3000/callback. After sign-out: http://localhost:3000.',
			'client_create with applicationType web, grantTypes authorization_code and refresh_token, tokenEndpointAuthMethod client_secret_basic',
			'Keep the secret only on the server, in an environment variable.'
		)
	},
	{
		id: 'spa',
		tab: 'product',
		ask: { actor: 'person', answer: 'spa' },
		title: 'A single-page app in the browser',
		sentence:
			'There is nowhere to keep a secret, so PKCE protects the sign-in: a one-time check string that only this browser tab knows.',
		protocol:
			'OpenID Connect · Authorization Code + PKCE · public application · refresh tokens',
		lanes: lanes('person', 'spa', 'fox', 'api'),
		steps: [
			step(
				'person',
				'spa',
				'Clicks “Sign in”',
				'The person clicks “Sign in” in your app.'
			),
			step(
				'spa',
				'fox',
				'Sign-in + PKCE',
				'Your app sends the browser to sign in, with a fingerprint of the check string.',
				'redirect'
			),
			step(
				'person',
				'fox',
				'Signs in',
				'The person signs in on the FoxAuth page.'
			),
			step(
				'fox',
				'spa',
				'One-time code',
				'FoxAuth sends the person back to your app with a one-time code.',
				'redirect'
			),
			step(
				'spa',
				'fox',
				'Code + check string',
				'Your app trades the code for tokens and shows the check string itself. A stolen code is useless without it.',
				'token'
			),
			step(
				'spa',
				'api',
				'Call with the token',
				'Your app calls your API with the access token.'
			)
		],
		problem: {
			at: 'spa',
			mark: 'secret',
			caption: 'A secret in browser code is public.'
		},
		fixCaption: 'A one-time check replaces the secret.',
		sees: {
			kind: 'signIn',
			lines: [
				'The FoxAuth sign-in page',
				'Password, or a provider button',
				'Then back to your app, signed in'
			]
		},
		preset: 'spa',
		needs: { room: 'applications', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'spa' } }
		},
		goodToKnow: [
			'There is no secret, and that is fine: PKCE does the protecting.',
			'Refresh tokens live a shorter time in a browser than on a server.',
			'Plain http is allowed only for localhost.',
			'Do not keep tokens in localStorage if the library can hold them in memory.'
		],
		prompt: prompt(
			'Add sign-in through FoxAuth to my single-page app (work out the framework from the code).\nFlow: Authorization Code + PKCE, a public application with no secret, refresh tokens.\nCallback: http://localhost:5173/callback. After sign-out: http://localhost:5173. Allowed origin (CORS): http://localhost:5173.',
			'client_create with applicationType web, tokenEndpointAuthMethod none, corsOrigins http://localhost:5173'
		)
	},
	{
		id: 'native',
		tab: 'product',
		ask: { actor: 'person', answer: 'native' },
		title: 'An app on a phone, a desktop or in a terminal',
		sentence:
			'Sign-in opens in the system browser, and the code comes back to your app on a local address, on any port.',
		protocol:
			'OpenID Connect · Authorization Code + PKCE · loopback redirect (RFC 8252)',
		lanes: lanes('person', 'app', 'fox'),
		steps: [
			step(
				'person',
				'app',
				'Starts sign-in',
				'The person clicks “Sign in” or runs your login command.'
			),
			step(
				'app',
				'fox',
				'Opens the browser',
				'Your app opens the system browser on the sign-in page, with PKCE.',
				'redirect'
			),
			step(
				'person',
				'fox',
				'Signs in',
				'The person signs in, in a browser they trust.'
			),
			step(
				'fox',
				'app',
				'Code to 127.0.0.1',
				'FoxAuth sends the code to http://127.0.0.1, on whatever port your app listens on right now.',
				'redirect'
			),
			step(
				'app',
				'fox',
				'Code + PKCE',
				'Your app trades the code for tokens.',
				'token'
			)
		],
		problem: {
			at: 'app',
			mark: 'password',
			caption: 'The app sees the person’s password.'
		},
		fixCaption: 'Sign-in opens in a browser they trust.',
		sees: {
			kind: 'signIn',
			lines: [
				'The FoxAuth sign-in page, in the system browser',
				'Then “you can close this tab”, from your app'
			]
		},
		preset: 'native',
		needs: { room: 'applications', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'native' } }
		},
		goodToKnow: [
			'One callback address covers every port, so you never register each run.',
			'There is no secret: the app is in the person’s hands and can be taken apart.',
			'An AI agent that runs on the person’s computer and signs in as them is set up exactly the same way.',
			'Do not use an embedded WebView for sign-in.'
		],
		prompt: prompt(
			'Add sign-in through FoxAuth to my native app (mobile, desktop or CLI: work it out from the code).\nFlow: Authorization Code + PKCE, a public application with no secret, sign-in in the system browser.\nCallback: http://127.0.0.1/callback, on a free port chosen at each run.',
			'client_create with applicationType native, tokenEndpointAuthMethod none, redirectUris http://127.0.0.1/callback'
		)
	},
	{
		id: 'device',
		tab: 'product',
		ask: { actor: 'person', answer: 'device' },
		title: 'A TV or a device with no keyboard',
		sentence:
			'The device shows a short code, and the person signs in on their phone.',
		protocol: 'OAuth 2.0 Device Authorization Grant (RFC 8628)',
		lanes: lanes('tv', 'fox', 'phone'),
		steps: [
			step(
				'tv',
				'fox',
				'Asks for a code',
				'The device asks FoxAuth for a sign-in code.'
			),
			step(
				'fox',
				'tv',
				'Code WDJB-MJHT',
				'FoxAuth returns a short code and an address. The device shows both.'
			),
			step(
				'phone',
				'fox',
				'Types the code, signs in',
				'The person opens the address on their phone, types the code and signs in as usual.'
			),
			step(
				'tv',
				'fox',
				'Done yet?',
				'Meanwhile the device asks every few seconds whether the code was confirmed.'
			),
			step(
				'fox',
				'tv',
				'Tokens',
				'As soon as the person has signed in, the device gets its tokens.',
				'token'
			)
		],
		problem: {
			at: 'tv',
			mark: 'password',
			caption: 'Typing a password with a TV remote.'
		},
		fixCaption: 'A short code, confirmed on a phone.',
		sees: {
			kind: 'deviceCode',
			lines: [
				'On the device: a short code and an address',
				'On the phone: a box for the code, then the usual sign-in'
			]
		},
		preset: 'device',
		needs: { flags: ['deviceFlow'], room: 'applications', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'device' } }
		},
		goodToKnow: [
			'The person needs a second screen: a phone or a computer.',
			'The code is short and expires quickly. There is nothing to store.',
			'Respect the polling interval and handle slow_down.'
		],
		prompt: prompt(
			'Add sign-in through FoxAuth to my app on a device with no keyboard.\nFlow: Device Authorization Grant (RFC 8628), a public application with no secret.\nShow the code and the address from the response on screen, then poll /token at the interval the response gives.',
			'client_create with applicationType native, grantTypes urn:ietf:params:oauth:grant-type:device_code, tokenEndpointAuthMethod none'
		)
	},
	{
		id: 'service',
		tab: 'product',
		ask: { actor: 'program', answer: 'service' },
		title: 'A program calls your API, with no person involved',
		sentence:
			'The program signs in by itself, with its own ID and secret, and gets a token in its own name.',
		protocol: 'OAuth 2.1 · Client Credentials',
		lanes: lanes('job', 'fox', 'api'),
		steps: [
			step(
				'job',
				'fox',
				'ID + secret',
				'The program shows its ID and its secret.'
			),
			step(
				'fox',
				'job',
				'Token for the API',
				'FoxAuth issues an access token.',
				'token'
			),
			step(
				'job',
				'api',
				'Call with the token',
				'The program calls your API with that token.'
			),
			step(
				'api',
				'api',
				'Checks the signature',
				'Your API checks the token’s signature against the project’s public keys. It does not call FoxAuth on every request.'
			)
		],
		problem: {
			at: 'job',
			mark: 'secret',
			caption: 'One shared key that never expires.'
		},
		fixCaption: 'Short-lived tokens replace the shared key.',
		sees: {
			kind: 'none',
			lines: ['Nobody sees a screen: no person signs in']
		},
		preset: 'service',
		needs: { flags: ['clientCredentials'], room: 'applications', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'service' } }
		},
		goodToKnow: [
			'The token speaks for the program. No person is in it.',
			'If the secret leaks, issue a new one in the console.',
			'Cache the token until it expires. Do not ask for a new one on every call.'
		],
		prompt: prompt(
			'Set up calls to my API from a background service through FoxAuth.\nFlow: Client Credentials, a confidential application (client_secret_basic), no person involved.',
			'client_create with grantTypes client_credentials, tokenEndpointAuthMethod client_secret_basic'
		)
	},
	{
		id: 'api',
		tab: 'product',
		ask: { actor: 'program', answer: 'api' },
		title: 'Your API accepts only your own apps',
		sentence:
			'Declare the API in your project, and FoxAuth writes it into each token as the recipient, so a token meant for another API is refused.',
		protocol:
			'OAuth 2.0 Resource Indicators (RFC 8707) · audience-bound tokens · introspection (RFC 7662) · revocation (RFC 7009)',
		lanes: lanes('webapp', 'fox', 'api', 'otherapi'),
		steps: [
			step(
				'webapp',
				'fox',
				'Token for your API',
				'Your app asks for a token and names the API it is for.'
			),
			step(
				'fox',
				'webapp',
				'Recipient: your API',
				'FoxAuth issues a token with the recipient written in it.',
				'token'
			),
			step(
				'webapp',
				'api',
				'Accepted',
				'Your API sees itself as the recipient and accepts the call.'
			),
			step(
				'webapp',
				'otherapi',
				'Refused',
				'The same token fails at another API: the recipient does not match.',
				'refusal'
			)
		],
		problem: {
			at: 'api',
			mark: 'open',
			caption: 'Your API accepts any token at all.'
		},
		fixCaption: 'Your API takes only its own tokens.',
		sees: {
			kind: 'none',
			lines: ['Nobody sees a screen: this is between programs']
		},
		needs: { room: 'apis', role: 'edit' },
		action: { kind: 'form', target: { area: 'apis', query: { declare: '1' } } },
		goodToKnow: [
			'An API address is unique within a project.',
			'Your app names the API when it asks for a token.',
			'Your API can ask FoxAuth whether a token is still valid, and an app can revoke a token it no longer needs, once a super administrator has switched introspection and revocation on.',
			'Refuse a token with another recipient (aud), even when its signature is valid.'
		],
		prompt: prompt(
			'Protect my API with FoxAuth tokens.\nThe API is declared as the resource https://api.example.com.\nIn the API, check the token signature against the project’s jwks_uri, the issuer (iss) and the recipient (aud = https://api.example.com). Apps must send resource=https://api.example.com when they ask for a token.',
			'resource_declare with the address https://api.example.com'
		)
	},
	{
		id: 'platform',
		tab: 'product',
		ask: { actor: 'program', answer: 'platform' },
		title: 'Other developers register their own apps on your platform',
		sentence:
			'Outside developers register an app by themselves with one request, and change or delete it with the token they got back.',
		protocol:
			'Dynamic Client Registration (RFC 7591) · Registration Management (RFC 7592)',
		lanes: lanes('dev', 'fox', 'person'),
		steps: [
			step(
				'dev',
				'fox',
				'Registers itself',
				'The developer’s app sends its details to the registration address.'
			),
			step(
				'fox',
				'dev',
				'ID + management token',
				'FoxAuth stores it as an application and returns its ID and a management token.',
				'token'
			),
			step(
				'person',
				'fox',
				'Signs in to it',
				'People sign in to that app like any other. The consent page says the app registered itself.'
			),
			step(
				'dev',
				'fox',
				'Updates or deletes it',
				'Later the app changes or removes its own registration with the management token.'
			)
		],
		problem: {
			at: 'dev',
			mark: 'secret',
			caption: 'You hand every developer a key yourself.'
		},
		fixCaption: 'Developers register their apps themselves.',
		sees: {
			kind: 'consent',
			lines: [
				'The consent page names the app',
				'It says the app registered itself'
			]
		},
		needs: { flags: ['registration'], role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the registration setting',
			target: { instance: 'settings', pane: 'endpoints' }
		},
		goodToKnow: [
			'It is a setting for the whole server, switched on by a super administrator.',
			'For MCP clients, prefer a description address (metadata URL): the MCP specification deprecates self-registration for them.',
			'Switching registration off stops new registrations. Apps already registered keep working.'
		],
		prompt: prompt(
			'Explain how an outside developer registers an app at my FoxAuth project’s registration_endpoint (from discovery), and how they update it with the registration access token.'
		)
	},
	{
		id: 'mcp',
		tab: 'product',
		ask: { actor: 'agent', answer: 'mcp' },
		title: 'Claude, Cursor or ChatGPT connect to your MCP server',
		sentence:
			'Declare your MCP server in your project, and an agent connects after a person signs in, with no registration: it introduces itself by the address of its own description.',
		protocol:
			'MCP Authorization · OAuth 2.1 · Protected Resource Metadata · Client ID Metadata Document',
		lanes: lanes('person', 'agent', 'mcp', 'fox'),
		steps: [
			step(
				'agent',
				'mcp',
				'Connects',
				'The agent tries to connect to your server.'
			),
			step(
				'mcp',
				'agent',
				'401: sign in at FoxAuth',
				'Your server answers that sign-in is needed, and names FoxAuth.',
				'refusal'
			),
			step(
				'agent',
				'fox',
				'Introduces itself',
				'The agent gives the address of its description (a metadata URL). It registers nothing beforehand.'
			),
			step(
				'person',
				'fox',
				'Signs in, allows',
				'The person signs in and sees which agent is asking for access.'
			),
			step(
				'fox',
				'agent',
				'Token for your server',
				'FoxAuth issues a token that works only for your server.',
				'token'
			),
			step(
				'agent',
				'mcp',
				'Calls tools',
				'The agent works with your server on the person’s behalf.'
			)
		],
		problem: {
			at: 'mcp',
			mark: 'open',
			caption: 'Your MCP server is open to anyone.'
		},
		fixCaption: 'The token works only at your server.',
		sees: {
			kind: 'agentConsent',
			lines: [
				'The sign-in page, then a consent page',
				'It names the agent and your MCP server',
				'The person allows or refuses'
			]
		},
		needs: {
			anyOf: ['clientIdMetadataDocument', 'registration'],
			room: 'apis',
			role: 'edit'
		},
		action: { kind: 'form', target: { area: 'apis', query: { declare: '1' } } },
		goodToKnow: [
			'The token is bound to your server. It does not work at anyone else’s MCP server.',
			'Your server checks the token itself, against the project’s public keys.',
			'Agents introduce themselves by a description address only while a super administrator has switched that on in the server’s settings. An agent that cannot host one needs registration switched on instead.',
			'Do not build client registration in your MCP server.'
		],
		prompt: prompt(
			'Add authorization through FoxAuth to my MCP server.\nThe server is declared as the resource https://mcp.example.com.\nServe /.well-known/oauth-protected-resource with authorization_servers set to the project’s issuer. Answer a request with no token with 401, WWW-Authenticate and resource_metadata.\nCheck the signature, iss, and aud = https://mcp.example.com.',
			'resource_declare with the address https://mcp.example.com'
		)
	},
	{
		id: 'connected',
		tab: 'product',
		ask: { actor: 'agent', answer: 'connected' },
		title: 'Your agent acts in the person’s Google, GitHub or Slack',
		sentence:
			'The person connects their account once, and after that the agent gets access through FoxAuth and keeps nobody’s tokens itself.',
		protocol: 'OAuth 2.0 Token Exchange (RFC 8693) · token vault',
		lanes: lanes('person', 'agent', 'fox', 'google'),
		steps: [
			step(
				'person',
				'fox',
				'Connects Google',
				'The person connects their account once and agrees.'
			),
			step(
				'google',
				'fox',
				'Access',
				'Google grants access. FoxAuth stores it encrypted.',
				'token'
			),
			step(
				'agent',
				'fox',
				'Exchanges its token',
				'The agent shows its own token and asks for this person’s Google access.'
			),
			step(
				'fox',
				'agent',
				'Google token',
				'FoxAuth hands over a Google token for this person only.',
				'token'
			),
			step(
				'agent',
				'google',
				'Acts',
				'The agent reads mail, creates a task or posts in a channel as the person.'
			)
		],
		problem: {
			at: 'agent',
			mark: 'password',
			caption: 'The agent holds the person’s Google keys.'
		},
		fixCaption: 'FoxAuth keeps the tokens, not the agent.',
		sees: {
			kind: 'serviceConsent',
			lines: [
				'A page that names the service, for example Google',
				'The person connects the account and agrees',
				'Later, a list of their connected accounts'
			]
		},
		needs: { room: 'connectedServices', role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'connected-services', query: { add: '1' } }
		},
		goodToKnow: [
			'You provide an app at that service: its ID and secret.',
			'The person sees their connected accounts and can disconnect any of them. The agent loses access at once.',
			'The agent only gets a token for the person who connected the account.',
			'Do not keep the Google token longer than one request.'
		],
		prompt: prompt(
			'Teach my agent to act in Google for the signed-in person through FoxAuth.\nGoogle is added to the project as a connected service.\nThe agent gets a Google token by exchanging its own token at /token (grant_type urn:ietf:params:oauth:grant-type:token-exchange). If the account is not connected yet, show the person the connect link.',
			'connected_service_create for Google'
		)
	},
	{
		id: 'adminmcp',
		tab: 'product',
		ask: { actor: 'agent', answer: 'adminmcp' },
		title: 'Manage FoxAuth from an AI agent',
		sentence:
			'The agent does in FoxAuth what you do in the console, with the same rights and the same checks and no special way in.',
		protocol: 'MCP · OAuth 2.1 protected resource',
		lanes: lanes('you', 'agent', 'fox'),
		steps: [
			step(
				'you',
				'agent',
				'“Create an application”',
				'You ask the agent in plain words.'
			),
			step(
				'agent',
				'fox',
				'Administrator sign-in',
				'The agent connects to /mcp. You sign in and allow it to act.'
			),
			step(
				'agent',
				'fox',
				'client_create',
				'The agent calls a tool: the same one behind the console button.'
			),
			step(
				'fox',
				'fox',
				'Same checks',
				'Rights, checks and plan limits are the console’s own.'
			),
			step(
				'fox',
				'fox',
				'Written to the trail',
				'The audit trail records who allowed it and which agent did it.'
			),
			step(
				'fox',
				'agent',
				'Result',
				'The agent gets the answer and tells you what was done.'
			)
		],
		problem: {
			at: 'agent',
			mark: 'secret',
			caption: 'The agent gets a key with every right.'
		},
		fixCaption: 'The agent acts with your rights only.',
		sees: {
			kind: 'adminConsent',
			lines: [
				'The administrator sign-in page',
				'A page that names the agent asking to act as you'
			]
		},
		/*
		 * No `super` role: any administrator connects their agent and it acts with their rights. A super administrator
		 * only permits which agents may connect, which Good to know says.
		 */
		needs: { flags: ['mcp'] },
		action: {
			kind: 'open',
			label: 'Open the MCP tools',
			target: { docs: '/docs/reference/mcp-tools/' }
		},
		goodToKnow: [
			'The agent acts with exactly your rights.',
			'The most dangerous acts, such as deleting a project, stay in the console.',
			'It is off until a super administrator switches it on in the server’s settings. FoxAuth Cloud has it on.',
			'Only an agent a super administrator has permitted can connect.'
		],
		prompt: [
			'Connect to the FoxAuth administrative MCP of the server whose console is at {console}. The address is the /mcp path of that server, and sign-in goes through OAuth.',
			'After signing in, call whoami and tell me which projects I can reach.',
			'Before any high-risk action, ask me again.'
		].join('\n')
	},

	/* Your product: more common tasks */
	{
		id: 'social',
		tab: 'product',
		title: 'Sign in with Google, GitHub, Apple or Microsoft',
		sentence:
			'The person signs in with an account they already have, and your app does not change because it still talks only to FoxAuth.',
		protocol: 'OpenID Connect · federation',
		lanes: lanes('person', 'webapp', 'fox', 'googleOnly'),
		steps: [
			step(
				'person',
				'webapp',
				'Clicks “Sign in”',
				'The person clicks “Sign in” in your app.'
			),
			step(
				'webapp',
				'fox',
				'Sends to sign-in',
				'Your app sends the person to FoxAuth, as before.',
				'redirect'
			),
			step(
				'person',
				'fox',
				'“Continue with Google”',
				'The person picks “Continue with Google”.'
			),
			step(
				'fox',
				'googleOnly',
				'Asks Google',
				'FoxAuth sends the person to Google.',
				'redirect'
			),
			step(
				'googleOnly',
				'fox',
				'This is anna@gmail.com',
				'Google confirms who it is.'
			),
			step(
				'fox',
				'webapp',
				'Tokens, as usual',
				'Your app gets the same tokens as after a password sign-in.',
				'token'
			)
		],
		problem: {
			at: 'webapp',
			mark: 'password',
			caption: 'People must invent yet another password.'
		},
		fixCaption: 'One button, for an account they already have.',
		sees: {
			kind: 'signIn',
			lines: [
				'The sign-in page shows a button for each provider',
				'“Continue with Google”',
				'Then Google’s own page, and back'
			]
		},
		needs: { flags: ['federation'], role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'identity-providers', query: { add: 'google' } }
		},
		goodToKnow: [
			'All four providers are on the Free plan.',
			'You provide an ID and a secret from the provider’s console.',
			'Microsoft on Free accepts accounts from any organisation. Limiting sign-in to one company’s directory is in the section for companies.',
			'Your app does not need to change.'
		],
		prompt: prompt(
			'Add sign-in through Google to my FoxAuth project.\nTell me where in Google Cloud Console to create the OAuth client and which callback address to give it, then connect it in FoxAuth.',
			'federation_provider_create for Google'
		)
	},
	{
		id: 'behindproxy',
		tab: 'product',
		title: 'A web app with no sign-in of its own',
		sentence:
			'Put the app behind your proxy. The proxy asks FoxAuth about each request before it reaches the app, so people sign in to your project and the app does not change.',
		protocol: 'Forward auth · OpenID Connect · Authorization Code + PKCE',
		lanes: lanes('browser', 'proxy', 'proxied', 'fox'),
		steps: [
			step(
				'browser',
				'proxy',
				'Opens the app',
				'The person opens your app. The request reaches your proxy first.'
			),
			step(
				'proxy',
				'fox',
				'Asks the project',
				'Your proxy asks the project whether this request may go through, before the app sees it.'
			),
			step(
				'fox',
				'browser',
				'Sends to sign-in',
				'Nobody is signed in yet, so the project sends the browser to its sign-in page.',
				'redirect'
			),
			step(
				'browser',
				'fox',
				'Signs in',
				'The person signs in to the project, or is already signed in to it.'
			),
			step(
				'fox',
				'browser',
				'Back to /_foxauth/callback',
				'The project sends the browser back to /_foxauth/callback on your app’s own address, and the app’s sign-in cookie is set there.',
				'redirect'
			),
			step(
				'fox',
				'proxy',
				'Yes, this is Anna',
				'On the next request the project checks your rules for that path and answers yes, with who the person is.'
			),
			step(
				'proxy',
				'proxied',
				'With X-Auth-* headers',
				'Your proxy lets the request through to your app, with the person’s id, email and groups in X-Auth-* headers.'
			)
		],
		problem: {
			at: 'proxied',
			mark: 'open',
			caption: 'Anyone who finds the address gets in.'
		},
		fixCaption: 'Your proxy lets in only the people you choose.',
		sees: {
			kind: 'signIn',
			lines: [
				'The project’s sign-in page, the first time',
				'Then your app, as before',
				'Someone not allowed sees a page that says so'
			]
		},
		preset: 'behindProxy',
		needs: { role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'applications', query: { situation: 'behindProxy' } }
		},
		goodToKnow: [
			'Make sure the app is reachable only through your proxy. A request that reaches it another way skips the check.',
			'Your app does not change. It can read who the person is from the X-Auth-* headers.',
			'The Connect step gives the configuration for Caddy, Traefik or nginx, ready to paste.',
			'Each path can be open to the members of chosen groups, to everyone in the project, to anyone, or to no one.',
			'There is nothing to switch on, and it is on every plan.'
		],
		prompt: prompt(
			'Put sign-in in front of my web app at https://app.example.com, behind my reverse proxy (work out Caddy, Traefik or nginx from my configuration). Only members of the group I name may open it.\nCreate the app behind the proxy in FoxAuth, then add the configuration it gives to my proxy.',
			'behind_proxy_app_create',
			'Make sure the app is reachable only through the proxy, so nobody can reach it without the check.'
		)
	},
	{
		id: 'signup',
		tab: 'product',
		title: 'People create their own account, or come by invitation',
		sentence:
			'Turn on sign-up and the sign-in page offers “Create an account”, or invite people yourself from the Users page.',
		protocol: 'OpenID Connect · email_verified',
		lanes: lanes('person', 'fox', 'mail'),
		steps: [
			step(
				'person',
				'fox',
				'Creates an account',
				'The person clicks “Create an account” and types an address.'
			),
			step(
				'fox',
				'mail',
				'Email with a link',
				'FoxAuth sends a confirmation email.'
			),
			step('person', 'mail', 'Opens the email', 'The person opens the email.'),
			step('person', 'fox', 'Confirms', 'They click the link.'),
			step(
				'fox',
				'fox',
				'Address proven',
				'The address is marked verified: your app gets email_verified = true.'
			)
		],
		problem: {
			at: 'person',
			mark: 'missing',
			caption: 'Every account is created by hand.',
			lanes: ['person']
		},
		fixCaption: 'People sign up, or accept an invitation.',
		sees: {
			kind: 'signUp',
			lines: [
				'A “Create an account” link on the sign-in page',
				'A form for the address and a password',
				'An email with a confirmation link'
			]
		},
		needs: { role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Sign-in',
			target: { area: 'sign-in' }
		},
		goodToKnow: [
			'Emails need a mail server (SMTP) set up.',
			'An address is marked verified only when the person really confirmed it.',
			'A forgotten password is reset by email, when the project allows it. The sign-in page then shows the link.'
		],
		prompt: prompt(
			'Turn on self sign-up in my FoxAuth project and check that SMTP is set up.',
			'project_update (sign-up) and smtp_settings_get',
			'If SMTP is not set up, tell me instead of turning sign-up on.'
		)
	},
	{
		id: 'totp',
		tab: 'product',
		title: 'A second factor at sign-in',
		sentence:
			'After the password, the person types a six-digit code from an authenticator app, and one switch turns it on for the whole project.',
		protocol: 'TOTP (RFC 6238)',
		lanes: lanes('person', 'fox', 'totp'),
		steps: [
			step('person', 'fox', 'Password', 'The person types their password.'),
			step(
				'fox',
				'person',
				'Code needed',
				'FoxAuth asks for the second-factor code.'
			),
			step(
				'totp',
				'person',
				'6 digits',
				'The authenticator app shows a code that changes every 30 seconds.'
			),
			step('person', 'fox', 'Types the code', 'The person types the code.'),
			step(
				'fox',
				'fox',
				'Signed in',
				'Sign-in is complete, and your app gets its tokens.',
				'token'
			)
		],
		problem: {
			at: 'person',
			mark: 'password',
			caption: 'A stolen password is enough to get in.',
			lanes: ['person']
		},
		fixCaption: 'A code from the phone is needed too.',
		sees: {
			kind: 'signIn',
			lines: [
				'The password page',
				'Then a page asking for a six-digit code',
				'On first use, a QR code to scan'
			]
		},
		needs: { role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Sign-in',
			target: { area: 'sign-in' }
		},
		goodToKnow: [
			'Any authenticator app works.',
			'If someone loses their phone, an administrator clears the second factor on their user page.'
		],
		prompt: prompt(
			'Turn on the second factor (TOTP) in my FoxAuth project.',
			'project_update (second factor)',
			'Tell me how many users have not set it up yet.'
		)
	},
	{
		id: 'domain',
		tab: 'product',
		title: 'Sign-in on your own address',
		sentence:
			'The sign-in page lives at your project’s own address: a path such as /yourshop, or a subdomain such as yourshop on this server. A super administrator can instead put it on your own domain, such as login.yourshop.com, so to the person it is your site.',
		protocol: 'One issuer per project',
		lanes: lanes('person', 'domain', 'fox'),
		steps: [
			step(
				'person',
				'domain',
				'Opens your address',
				'The person opens the project’s address: a path, a subdomain or a domain of your own.'
			),
			step(
				'domain',
				'fox',
				'Reaches FoxAuth',
				'The address leads to FoxAuth. A domain of your own needs a DNS record that points to it.'
			),
			step(
				'fox',
				'fox',
				'Finds the project',
				'FoxAuth finds the project by its address. The project has its own issuer and its own signing keys.'
			),
			step(
				'fox',
				'person',
				'Your sign-in page',
				'The person signs in on a page with your address.'
			)
		],
		problem: {
			at: 'domain',
			mark: 'missing',
			caption: 'Sign-in happens on someone else’s address.'
		},
		fixCaption: 'Sign-in happens on your own address.',
		sees: {
			kind: 'signIn',
			lines: ['The sign-in page, with your address in the address bar']
		},
		needs: { planFeature: 'customSlug', role: 'changeAddress' },
		action: {
			kind: 'open',
			label: 'Open Settings',
			target: { area: 'settings' }
		},
		goodToKnow: [
			'A project has exactly one of the three addresses: a path, a subdomain or a domain of its own.',
			'An owner of the project’s team changes its path or subdomain, and only while the project holds no application, identity provider, provisioning connection or connected service.',
			'After that, a super administrator changes it. A domain of your own is always a super administrator’s to set.',
			'A domain of your own needs a DNS record and an https certificate.',
			'Changing the address changes the issuer, so update it in your apps.'
		],
		prompt: prompt(
			'Give my FoxAuth project the address name yourshop, as a path or a subdomain, and tell me what changes for my apps.',
			'project_address_change',
			'Remind me to update the issuer address in my apps.'
		)
	},
	{
		id: 'logout',
		tab: 'product',
		title: 'Sign out of one app, and out of all of them',
		sentence:
			'When the person signs out of one of your apps, FoxAuth ends their session and tells every other app they used so it can sign them out too.',
		protocol: 'OIDC RP-Initiated Logout · OIDC Back-Channel Logout',
		lanes: lanes('person', 'webapp', 'fox', 'apps'),
		steps: [
			step(
				'person',
				'webapp',
				'Clicks “Sign out”',
				'The person clicks “Sign out” in one of your apps.'
			),
			step(
				'webapp',
				'fox',
				'End the session',
				'Your app sends the person to FoxAuth’s sign-out address.',
				'redirect'
			),
			step('fox', 'fox', 'Session ended', 'FoxAuth ends the person’s session.'),
			step(
				'fox',
				'apps',
				'Sign-out notice',
				'FoxAuth sends a sign-out notice, server to server, to every other app the person used.'
			),
			step(
				'fox',
				'person',
				'Signed out',
				'The person lands on your “signed out” page.',
				'redirect'
			)
		],
		problem: {
			at: 'apps',
			mark: 'open',
			caption: 'Signing out leaves the other apps open.'
		},
		fixCaption: 'One sign-out reaches every app.',
		sees: {
			kind: 'none',
			lines: [
				'Your own “signed out” page',
				'Other apps sign the person out without a page'
			]
		},
		needs: { flags: ['rpInitiatedLogout'], role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Applications',
			target: { area: 'applications' }
		},
		goodToKnow: [
			'Each app that should hear about it gives FoxAuth a sign-out notice address.',
			'The notice goes from server to server, so it works even when the app’s tab is closed.',
			'Sign-out notices are sent only while a super administrator has switched back-channel logout on in the server’s settings.',
			'Check the logout token signature, iss, aud and the events claim before ending the session.'
		],
		prompt: prompt(
			'Add sign-out through FoxAuth to my app: send the person to the end_session_endpoint from discovery with id_token_hint and post_logout_redirect_uri, and add a back-channel logout endpoint that validates the logout token and ends the local session.',
			'client_update with postLogoutRedirectUris and backchannelLogoutUri'
		)
	},
	{
		id: 'branding',
		tab: 'product',
		title: 'Sign-in that looks like your product',
		sentence:
			'Give your application its logo and its primary colour, and the sign-in pages wear them in English, Russian or Simplified Chinese.',
		protocol: 'OpenID Connect ui_locales · logo · primary colour',
		lanes: lanes('person', 'webapp', 'fox'),
		steps: [
			step(
				'person',
				'webapp',
				'Clicks “Sign in”',
				'The person clicks “Sign in” in your app.'
			),
			step(
				'webapp',
				'fox',
				'Sign-in, ui_locales=ru',
				'Your app sends them to sign in, and may say which language it prefers.',
				'redirect'
			),
			step(
				'fox',
				'fox',
				'Logo, colour, language',
				'FoxAuth picks your colour, your logo for the consent page, and the person’s language.'
			),
			step(
				'fox',
				'person',
				'Your look, their language',
				'The person signs in on a page that looks like your product.'
			)
		],
		problem: {
			at: 'webapp',
			mark: 'missing',
			caption: 'The sign-in page looks like someone else’s.'
		},
		fixCaption: 'Your logo, your colour, their language.',
		sees: {
			kind: 'signIn',
			lines: [
				'Your primary colour on every sign-in page',
				'Your logo and name on the consent page',
				'The person’s language'
			]
		},
		needs: { role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Applications',
			target: { area: 'applications' }
		},
		goodToKnow: [
			'The logo is an image you upload: PNG, JPEG or WebP, up to 64 KiB.',
			'They show for an application of your own organisation, not on a device sign-in, and not when every callback address is local.',
			'FoxAuth shifts the colour to the nearest readable shade, in light and in dark mode.',
			'The language is the person’s own choice first, then your app’s ui_locales, then the browser’s. The console and administrator emails stay in English.'
		],
		prompt: prompt(
			'Give my FoxAuth application its logo and primary colour, and pass ui_locales from my app’s current language when it sends people to sign in.',
			'client_update with logo and primaryColor'
		)
	},
	{
		id: 'myapps',
		tab: 'product',
		title: 'People see and remove the apps that can reach their account',
		sentence:
			'Every project has an account page that lists the apps holding access to the signed-in person, and they can remove any of them.',
		protocol: 'Grant management for end users',
		lanes: lanes('person', 'fox'),
		steps: [
			step(
				'person',
				'fox',
				'Opens /account/apps',
				'The person opens the account page of your project.'
			),
			step(
				'fox',
				'person',
				'Apps with access',
				'FoxAuth lists the apps that can reach their account.'
			),
			step('person', 'fox', 'Removes one', 'The person removes an app.'),
			step(
				'fox',
				'fox',
				'Access ended',
				'FoxAuth ends that app’s access. The next time the app asks, it is refused.',
				'refusal'
			)
		],
		problem: {
			at: 'person',
			mark: 'missing',
			caption: 'People cannot see which apps reach them.'
		},
		fixCaption: 'People see every app, and remove any.',
		sees: {
			kind: 'none',
			lines: [
				'A list of the apps that can reach their account',
				'A button to remove each one'
			]
		},
		needs: {},
		action: {
			kind: 'open',
			label: 'Open the account page',
			target: { projectPage: 'account/apps' }
		},
		goodToKnow: [
			'There is nothing to switch on.',
			'The page lives at your project’s own address, at /account/apps.',
			'Link to it from your app’s account settings.'
		],
		prompt: prompt(
			'Add a “Connected apps” link to my app’s account settings that opens {issuer}/account/apps.'
		)
	},
	{
		id: 'bound',
		tab: 'product',
		title: 'A stolen token is useless',
		sentence:
			'With DPoP, each token works only together with a fresh proof signed by a key that never leaves your app, so a copied token on its own is refused.',
		protocol: 'DPoP (RFC 9449) · mTLS certificate-bound tokens (RFC 8705)',
		lanes: lanes('webapp', 'fox', 'api', 'thief'),
		steps: [
			step(
				'webapp',
				'fox',
				'Token + key proof',
				'Your app asks for a token and signs a proof with its own key.'
			),
			step(
				'fox',
				'webapp',
				'Token bound to the key',
				'FoxAuth binds the token to that key.',
				'token'
			),
			step(
				'webapp',
				'api',
				'Token + new proof',
				'Each call carries the token and a new proof.'
			),
			step(
				'thief',
				'api',
				'Copied token',
				'Someone with a copy of the token has no key, so your API refuses it.',
				'refusal'
			)
		],
		problem: {
			at: 'thief',
			mark: 'copy',
			caption: 'A copied token works for anyone.'
		},
		fixCaption: 'A token works only with your app’s key.',
		sees: {
			kind: 'none',
			lines: ['Nobody sees a screen: this is between your app and your API']
		},
		needs: { flags: ['dpop'], role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Applications',
			target: { area: 'applications' }
		},
		goodToKnow: [
			'Your API checks the DPoP proof along with the token.',
			'Client certificates (mTLS) do the same job, on your own server only.'
		],
		prompt: prompt(
			'Make my app use DPoP with FoxAuth: generate a key pair kept in memory, send a DPoP proof with every token request and every API call, and make my API verify the proof (htm, htu, ath, jti) as well as the token’s cnf.jkt.',
			'client_update with dpopBoundAccessTokens true'
		)
	},

	/* Enterprise: your customer is a company */
	{
		id: 'okta',
		tab: 'enterprise',
		title: 'Company sign-in',
		sentence:
			'Add the company’s sign-in provider, any OpenID provider or one organisation’s Microsoft directory, and your app does not change.',
		protocol: 'OpenID Connect · federation',
		lanes: lanes('employee', 'webapp', 'fox', 'idp'),
		steps: [
			step('employee', 'webapp', 'Signs in', 'The employee clicks “Sign in”.'),
			step(
				'webapp',
				'fox',
				'Sends to sign-in',
				'Your app sends them to FoxAuth, as usual.',
				'redirect'
			),
			step(
				'fox',
				'idp',
				'To the company’s Okta',
				'FoxAuth sends the employee to their company’s provider.',
				'redirect'
			),
			step(
				'idp',
				'fox',
				'Employee confirmed',
				'The company’s provider confirms who it is.'
			),
			step('fox', 'webapp', 'Tokens', 'Your app gets ordinary tokens.', 'token')
		],
		problem: {
			at: 'webapp',
			mark: 'password',
			caption: 'Your app keeps passwords company IT cannot close.'
		},
		fixCaption: 'Employees sign in with their company account.',
		next: 'scim',
		sees: {
			kind: 'companySignIn',
			lines: [
				'A button with the company’s name on the sign-in page',
				'Then the company’s own sign-in page, and back'
			]
		},
		needs: {
			flags: ['federation'],
			planFeature: 'enterpriseSignIn',
			role: 'edit'
		},
		action: {
			kind: 'form',
			target: { area: 'identity-providers', query: { add: 'oidc' } }
		},
		first: true,
		goodToKnow: [
			'What you ask the company’s IT department for: the provider address, an ID and a secret.',
			'It usually comes with the next one: the company also wants its directory to create and remove people.'
		],
		prompt: prompt(
			'Connect company sign-in through the customer’s OpenID provider (Okta) to my FoxAuth project. Tell me what to ask the customer’s IT department for.',
			'federation_provider_create with kind oidc'
		)
	},
	{
		id: 'scim',
		tab: 'enterprise',
		title: 'People arrive and leave by themselves',
		sentence:
			'A SCIM connection lets the company’s directory create, change and deactivate people in your project, while your apps keep asking FoxAuth who may sign in.',
		protocol: 'SCIM 2.0 (RFC 7644)',
		lanes: lanes('dir', 'fox', 'employee'),
		steps: [
			step(
				'dir',
				'fox',
				'Joined: create',
				'Someone joins the company. The directory creates them in FoxAuth.'
			),
			step(
				'dir',
				'fox',
				'Moved: update',
				'They move to another department. The directory updates the record.'
			),
			step(
				'dir',
				'fox',
				'Left: deactivate',
				'They leave. The directory deactivates them.'
			),
			step(
				'employee',
				'fox',
				'Tries to sign in',
				'Later they try to sign in to one of your apps.'
			),
			step(
				'fox',
				'employee',
				'Refused',
				'FoxAuth refuses. Nothing is sent to your app: it simply never gets a token for them.',
				'refusal'
			)
		],
		problem: {
			at: 'employee',
			mark: 'missing',
			caption: 'Every person is added and removed by hand.',
			lanes: ['dir', 'employee']
		},
		fixCaption: 'The company’s directory adds and removes people.',
		next: 'okta',
		sees: {
			kind: 'none',
			lines: [
				'The company’s IT department sees the connection in its directory',
				'A person who left sees a refusal at sign-in'
			]
		},
		needs: { flags: ['scim'], role: 'edit' },
		action: {
			kind: 'form',
			target: { area: 'provisioning', query: { new: '1' } }
		},
		first: true,
		goodToKnow: [
			'You give the company’s IT a SCIM address and a token. They work with Entra ID or Okta.',
			'A person from the directory is read-only in the console, except the local lock.',
			'It usually comes with company sign-in, and works with a sign-in provider you have already added.'
		],
		prompt: prompt(
			'Create a SCIM connection for Entra ID in my FoxAuth project, and tell me what the customer’s IT department enters on their side.',
			'provisioning_connection_create'
		)
	},
	{
		id: 'groups',
		tab: 'enterprise',
		title: 'Department and role in the token',
		sentence:
			'Put people into project groups, and your app gets them in the token’s groups field and decides what to show.',
		protocol: 'OpenID Connect · groups claim',
		lanes: lanes('person', 'webapp', 'fox'),
		steps: [
			step('person', 'webapp', 'Signs in', 'Anna signs in to your app.'),
			step(
				'fox',
				'fox',
				'Anna is in Finance',
				'In the project, Anna is a member of the Finance group.'
			),
			step(
				'fox',
				'webapp',
				'groups: Finance',
				'Your app gets her groups in the token.',
				'token'
			),
			step(
				'webapp',
				'webapp',
				'Shows the right part',
				'Your app opens the finance section for Anna.'
			)
		],
		problem: {
			at: 'webapp',
			mark: 'missing',
			caption: 'Your app cannot tell the person’s department.'
		},
		fixCaption: 'The department arrives in the token.',
		sees: {
			kind: 'none',
			lines: ['Nobody sees a screen: the groups arrive in the token']
		},
		needs: { role: 'edit' },
		action: {
			kind: 'open',
			label: 'Open Groups',
			target: { area: 'groups' }
		},
		goodToKnow: [
			'The company’s directory can send the groups too, through SCIM.'
		],
		prompt: prompt(
			'Create a Finance group in my FoxAuth project, and show me how to read the groups field in my app.',
			'project_group_create'
		)
	},
	{
		id: 'offboard',
		tab: 'enterprise',
		title: 'Someone left: access closed everywhere',
		sentence:
			'Deactivate the person in FoxAuth, or let the company’s provider sign them out everywhere by itself.',
		protocol: 'Okta Universal Logout · OIDC Back-Channel Logout',
		lanes: lanes('itadmin', 'idp', 'fox', 'apps'),
		steps: [
			step(
				'itadmin',
				'idp',
				'Deactivates',
				'The IT department deactivates the employee on their side.'
			),
			step(
				'idp',
				'fox',
				'Sign out everywhere',
				'The company’s provider tells FoxAuth to sign the person out.'
			),
			step(
				'fox',
				'fox',
				'Sessions ended',
				'FoxAuth ends the sessions and revokes the tokens.',
				'refusal'
			),
			step(
				'fox',
				'apps',
				'Sign-out notice',
				'Your apps receive a sign-out notice.'
			)
		],
		problem: {
			at: 'apps',
			mark: 'open',
			caption: 'Someone left, and their access is still open.'
		},
		fixCaption: 'One change closes access everywhere.',
		sees: {
			kind: 'none',
			lines: ['The person is signed out of every app, with no page to see']
		},
		needs: { role: 'manageUsers' },
		action: {
			kind: 'open',
			label: 'Open Users',
			target: { area: 'users' }
		},
		goodToKnow: [
			'You can do it by hand: Users, the person, Deactivate.',
			'The company’s provider can do it for you only after you add it as a sign-in provider and a super administrator switches on the signals it sends, in the server’s settings.'
		],
		prompt: prompt(
			'Deactivate the user anna@acme.com in my FoxAuth project and end all of their sessions.',
			'project_user_update and project_user_sign_out'
		)
	},
	{
		id: 'idjag',
		tab: 'enterprise',
		title: 'The company’s agents, with no consent screen',
		sentence:
			'The company’s provider gives the agent an assertion, and FoxAuth trades it for a token, so access stays under the company’s control.',
		protocol: 'ID-JAG · OAuth 2.0 Token Exchange (RFC 8693) · JWT bearer',
		lanes: lanes('agent', 'idp', 'fox', 'api'),
		steps: [
			step(
				'agent',
				'idp',
				'Asks for access',
				'The agent asks the company’s provider for access to your app.'
			),
			step(
				'idp',
				'agent',
				'Assertion',
				'The provider issues an assertion (an ID-JAG).',
				'token'
			),
			step(
				'agent',
				'fox',
				'Trades it',
				'The agent presents the assertion to FoxAuth.'
			),
			step(
				'fox',
				'agent',
				'Token',
				'FoxAuth issues a token, with no consent screen.',
				'token'
			),
			step('agent', 'api', 'Works', 'The agent calls your API.')
		],
		problem: {
			at: 'agent',
			mark: 'missing',
			caption: 'No person is there to click Allow.',
			lanes: ['agent', 'api']
		},
		fixCaption: 'The company vouches for its own agents.',
		sees: {
			kind: 'none',
			lines: ['Nobody sees a consent screen: the company has already decided']
		},
		needs: {
			flags: ['jwtBearer'],
			planFeature: 'enterpriseSignIn',
			role: 'edit'
		},
		action: {
			kind: 'open',
			label: 'Open Identity providers',
			target: { area: 'identity-providers' }
		},
		goodToKnow: [
			'Trust is switched on at the sign-in provider: “Accept assertions”.',
			'These tokens come with no refresh token.',
			'Assertions never reach the administrative MCP or SCIM.'
		],
		prompt: prompt(
			'Turn on accepting ID-JAG assertions from the company sign-in provider in my FoxAuth project, and explain how an agent trades an assertion for a token.',
			'federation_provider_update'
		)
	},
	{
		id: 'rar',
		tab: 'enterprise',
		title: 'The person approves one exact action',
		sentence:
			'Your app asks for one action described in detail, the consent page shows exactly that action, and the token carries it and nothing more.',
		protocol: 'Rich Authorization Requests (RFC 9396) · authorization_details',
		lanes: lanes('webapp', 'fox', 'person', 'api'),
		steps: [
			step(
				'webapp',
				'fox',
				'Approve: pay €100',
				'Your app asks for a token for one payment, described in detail.'
			),
			step(
				'fox',
				'person',
				'Shows the payment',
				'FoxAuth shows the person the payment itself.'
			),
			step('person', 'fox', 'Approves', 'The person approves it.'),
			step(
				'fox',
				'webapp',
				'Token for this payment',
				'FoxAuth issues a token that carries this payment and nothing more.',
				'token'
			),
			step(
				'webapp',
				'api',
				'Pays €100',
				'Your payment API reads the details from the token and carries them out.'
			)
		],
		problem: {
			at: 'api',
			mark: 'open',
			caption: 'One yes allows far more than was meant.',
			lanes: ['person', 'webapp', 'api']
		},
		fixCaption: 'The person approves one exact action.',
		sees: {
			kind: 'approve',
			lines: [
				'The consent page shows the payment: the amount and the account',
				'The person approves that payment and nothing else'
			]
		},
		needs: { flags: ['richAuthorizationRequests'], role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the setting',
			target: { instance: 'settings', pane: 'request-security' }
		},
		goodToKnow: [
			'Each kind of action is declared once in the server’s settings, with the label the consent page shows.',
			'The details go only into a token for one declared API.',
			'It works with sign-in codes and refresh tokens, not with the other flows.'
		],
		prompt: prompt(
			'Make my app request a payment with authorization_details of type https://scheme.example/payment (actions: initiate, amount, currency, creditor account) and resource set to my payment API, and make the API read authorization_details from the token.'
		)
	},
	{
		id: 'ciba',
		tab: 'enterprise',
		title: 'Approve on your phone',
		sentence:
			'The request reaches the person on their phone, and the system that asked gets the token.',
		protocol: 'OpenID Connect CIBA',
		lanes: lanes('operator', 'fox', 'client'),
		steps: [
			step(
				'operator',
				'fox',
				'Confirm for Anna',
				'The call centre system asks for Anna’s approval.'
			),
			step(
				'fox',
				'client',
				'Request to the phone',
				'Anna gets the request on her phone.'
			),
			step('client', 'fox', 'Approves', 'Anna approves.'),
			step(
				'fox',
				'operator',
				'Tokens',
				'The system gets its tokens and carries on.',
				'token'
			)
		],
		problem: {
			at: 'client',
			mark: 'password',
			caption: 'Customers say their password out loud.',
			lanes: ['client', 'operator']
		},
		fixCaption: 'The customer approves on their own phone.',
		sees: {
			kind: 'approve',
			lines: [
				'On the person’s phone: who is asking, and for what',
				'Approve or refuse'
			]
		},
		needs: { flags: ['ciba'], role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the setting',
			target: { instance: 'settings', pane: 'grants' }
		},
		goodToKnow: [
			'It is a setting for the whole server, switched on by a super administrator.'
		],
		prompt: prompt(
			'Explain how to switch CIBA on in FoxAuth, and how a call centre system sends an approval request.'
		)
	},
	{
		id: 'ipsie',
		tab: 'enterprise',
		title: 'The strictest profile',
		sentence:
			'The IPSIE SL1 profile comes with one switch, and a readiness check first shows what will change.',
		protocol: 'IPSIE SL1 · DPoP (RFC 9449) · PKCE',
		lanes: lanes('security', 'fox'),
		steps: [
			step(
				'security',
				'fox',
				'Readiness check',
				'You run the readiness check.'
			),
			step(
				'fox',
				'security',
				'What will change',
				'FoxAuth lists the applications that would stop working.'
			),
			step('security', 'fox', 'Switch it on', 'You switch the profile on.'),
			step(
				'fox',
				'fox',
				'Strict rules',
				'The rules now apply to every application.'
			)
		],
		problem: {
			at: 'security',
			mark: 'missing',
			caption: 'Nobody can tell which rules are enforced.'
		},
		fixCaption: 'A readiness check, then one strict switch.',
		sees: {
			kind: 'none',
			lines: ['A readiness report in the console, before anything changes']
		},
		needs: { flags: ['ipsieSl1'], role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the setting',
			target: { instance: 'settings', pane: 'request-security' }
		},
		goodToKnow: [
			'Run the readiness check first: it names the applications that would stop working.',
			'Each token is bound to the application’s key with DPoP, so a stolen token is useless.',
			'PKCE is required on every sign-in, and only applications registered in advance may sign in.',
			'Signatures use PS256, ES256 or EdDSA.',
			'A separate setting, FAPI behaviours, also makes an application’s signed assertion name this server as its only audience.',
			'It is a setting for the whole server.'
		],
		prompt: prompt(
			'Check whether my FoxAuth server is ready for the IPSIE SL1 profile, and list what needs fixing.',
			'settings_ipsie_profile_readiness_get'
		)
	},
	{
		id: 'teams',
		tab: 'enterprise',
		title: 'Teams and an audit trail',
		sentence:
			'Teams own projects, membership is the only thing that grants access, and every change goes into a trail that nobody can edit.',
		protocol: 'Immutable audit trail',
		lanes: lanes('team', 'project', 'audit'),
		steps: [
			step('team', 'project', 'Owns', 'The Payments team owns its projects.'),
			step(
				'team',
				'project',
				'Members work',
				'Only the team’s members can reach the project.'
			),
			step(
				'project',
				'audit',
				'Every change',
				'Every change is written to the trail.'
			),
			step(
				'audit',
				'audit',
				'Cannot be edited',
				'Nobody can change or delete an entry.'
			)
		],
		problem: {
			at: 'team',
			mark: 'copy',
			caption: 'Everyone shares one administrator account.'
		},
		fixCaption: 'Each team reaches only its own projects.',
		sees: {
			kind: 'none',
			lines: ['The trail in the console: who changed what, and when']
		},
		needs: {},
		action: {
			kind: 'open',
			label: 'Open Teams',
			target: { section: 'teams' }
		},
		goodToKnow: [
			'There are no roles: membership of a team grants access.',
			'The trail is under Audit, in the menu.'
		],
		prompt: prompt(
			'Create a Payments team in FoxAuth and show me the latest entries in the audit trail.',
			'team_create and audit_list'
		)
	},
	{
		id: 'adminapps',
		tab: 'enterprise',
		title: 'A tool for your administrators only',
		sentence:
			'Register the tool as an application in the administrators’ project, and the groups field names the administrator’s teams.',
		protocol: 'OpenID Connect · groups claim',
		lanes: lanes('admin', 'tool', 'fox'),
		steps: [
			step(
				'admin',
				'tool',
				'Opens it',
				'An administrator opens the internal tool.'
			),
			step(
				'tool',
				'fox',
				'Administrator sign-in',
				'The tool sends them to the administrators’ sign-in.',
				'redirect'
			),
			step(
				'fox',
				'tool',
				'groups: their teams',
				'The tool gets the administrator’s teams.',
				'token'
			),
			step(
				'tool',
				'tool',
				'Lets the right teams in',
				'The tool opens itself to the teams it trusts.'
			)
		],
		problem: {
			at: 'tool',
			mark: 'open',
			caption: 'Anyone can open the internal tool.'
		},
		fixCaption: 'Only your administrators get in.',
		sees: {
			kind: 'signIn',
			lines: ['The administrators’ sign-in page, then back to the tool']
		},
		needs: { role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the administrators’ applications',
			target: { instance: 'administrators', area: 'applications' }
		},
		goodToKnow: [
			'A super administrator registers it, and only in the console.',
			'Sign-in only: such applications get no tokens for an API.'
		],
		prompt:
			'Explain how a super administrator registers an internal tool as an application in the administrators’ project, in the console at {console}. An agent cannot do this: it is withheld from agents.'
	},
	{
		id: 'consolesso',
		tab: 'enterprise',
		title: 'Your administrators sign in to the console with company SSO',
		sentence:
			'Add the company’s provider to the administrators’ project, and the console’s sign-in page offers it while FoxAuth makes sure the console can never lock itself.',
		protocol: 'OpenID Connect · federation into the console',
		lanes: lanes('admin', 'fox', 'idp'),
		steps: [
			step(
				'admin',
				'fox',
				'Opens the console',
				'An administrator opens the console and picks the company provider.'
			),
			step(
				'fox',
				'idp',
				'To the company’s Okta',
				'FoxAuth sends them to the company’s provider.',
				'redirect'
			),
			step(
				'idp',
				'fox',
				'Administrator confirmed',
				'The provider confirms who it is.'
			),
			step(
				'fox',
				'fox',
				'Finds the administrator',
				'FoxAuth links them to their existing administrator account.'
			),
			step(
				'fox',
				'admin',
				'In the console',
				'The administrator is in the console.'
			)
		],
		problem: {
			at: 'admin',
			mark: 'password',
			caption: 'The console needs a password of its own.',
			lanes: ['admin', 'idp']
		},
		fixCaption: 'Administrators use their company sign-in.',
		sees: {
			kind: 'companySignIn',
			lines: [
				'The console’s sign-in page with a button for the company',
				'Then the company’s own sign-in page, and back'
			]
		},
		needs: { flags: ['federation'], role: 'super' },
		action: {
			kind: 'open',
			label: 'Open the administrators’ sign-in providers',
			target: { instance: 'administrators', area: 'identity-providers' }
		},
		goodToKnow: [
			'Only a super administrator configures it.',
			'A new provider admits only people who already have an administrator account. Linking the first time needs their password.',
			'Passwords can be switched off only while a super administrator can still come in through the provider.'
		],
		prompt:
			'Explain how a super administrator adds the company’s sign-in provider to the administrators’ project, in the console at {console}, so administrators can sign in with company SSO.'
	}
];

/* What is preselected on each tab, so the page is never empty. */
export const DEFAULT_ANSWER: Readonly<Record<GuideTab, string>> = {
	product: 'server',
	enterprise: 'okta'
};

const BY_ID: ReadonlyMap<string, GuideSituation> = new Map(
	GUIDE_SITUATIONS.map((situation) => [situation.id, situation])
);

export function guideSituation(id: string): GuideSituation | undefined {
	return BY_ID.get(id);
}
