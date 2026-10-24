/*
 * Card text is keyed by a stable name rather than listed in order, so the view can attach a card's
 * flag and spec link to its text by name; a reordering on one side cannot pair a body with the
 * wrong setting.
 */
export default {
	title: 'OAuth 2.1 and OpenID Connect features',
	description:
		'Every grant, profile and control OAuth-server.ts implements: OAuth 2.1 with PKCE, DPoP, PAR, FAPI, CIBA and mTLS, an audited console, and OAuth for MCP servers.',
	hero: {
		eyebrow: 'Features',
		heading:
			'Every feature ships in one OAuth 2.1 server. Most are switched off.',
		lead: 'FoxAuth ships one OAuth 2.1 and OpenID Connect authorization server, with no feature editions. Authorization Code with PKCE and OpenID Connect run from the first start, and most of the rest wait behind a named flag. In practice your attack surface is the set of features you asked for. Each card says whether its feature is on from the first start or waits for its flag.',
		cloud:
			'On FoxAuth Cloud the flags are ours to set, and a plan limits what each project may create. On your own servers both are yours, and plans are off unless you turn them on. A card marked On in FoxAuth Cloud is switched on there.',
		/* The badge on a card whose flag is on at FoxAuth Cloud. */
		cloudBadge: 'On in FoxAuth Cloud',
		flags:
			'Each flag below links to its entry in the Settings reference, which is generated from the code and names the default and the consequence.',
		getStarted: 'Get started',
		settingsReference: 'Settings reference'
	},
	groups: {
		protocol: {
			heading: 'Protocol',
			title: 'Every OAuth 2.1 grant, plus device flow and CIBA.',
			blurb:
				'The grants and endpoints. Authorization Code with PKCE and OpenID Connect are always on; most of the rest wait for a flag.',
			items: {
				pkce: {
					title: 'Authorization Code with PKCE',
					body: 'By default PKCE is mandatory for every client, public or confidential, as OAuth 2.1 requires. Redirect URIs match exactly.'
				},
				oidc: {
					title: 'OpenID Connect Core 1.0',
					body: 'ID tokens, the UserInfo endpoint and discovery, with the standard claim set and pairwise subjects.'
				},
				sessionExpiry: {
					title: 'Session expiry in every ID token',
					body: 'Every ID token says when the application must send the person back to sign in (session_expiry). A federated session ends no later than the time the upstream provider sets.'
				},
				issuerIdentification: {
					title: 'Issuer identification',
					body: 'Every authorization response carries iss, so a client that checks it cannot be tricked into accepting another issuer’s code.'
				},
				resourceIndicators: {
					title: 'Resource Indicators',
					body: 'Audience-restrict a token with the resource parameter, and validate it at the resource server. On by default.'
				},
				clientCredentials: {
					title: 'Client Credentials grant',
					body: 'Machine-to-machine tokens with no end user, scoped per client.'
				},
				refreshToken: {
					title: 'Refresh Token grant',
					body: 'Long-lived sessions with rotation and reuse detection. Replay a token and the whole grant is revoked. On by default: offered while offline_access is a supported scope.'
				},
				deviceFlow: {
					title: 'Device Authorization Grant',
					body: 'Sign in on a TV or a CLI by typing a user code on another device.'
				},
				ciba: {
					title: 'CIBA',
					body: 'Client-initiated backchannel authentication: the client asks, the user approves out of band.'
				},
				par: {
					title: 'Pushed Authorization Requests',
					body: 'The client posts the request to the server first and sends only a request_uri through the browser.'
				},
				requestObjects: {
					title: 'Request objects',
					body: 'Signed request and request_uri parameters, so the authorization request itself is integrity-protected.'
				},
				jarm: {
					title: 'JARM',
					body: 'JWT-secured authorization responses, signed and optionally encrypted.'
				},
				rar: {
					title: 'Rich Authorization Requests',
					body: 'Fine-grained authorization_details instead of a scope string, for payments and similar.'
				},
				introspection: {
					title: 'Token introspection',
					body: 'Resource servers ask the issuer whether a token is still active, and what it carries.'
				},
				jwtIntrospection: {
					title: 'JWT introspection responses',
					body: 'Signed introspection responses, for a resource server that must prove what it was told.'
				},
				revocation: {
					title: 'Token revocation',
					body: 'A client retires an access or refresh token it no longer needs.'
				},
				jwtUserinfo: {
					title: 'Signed UserInfo responses',
					body: 'Return UserInfo as a signed JWT instead of plain JSON.'
				},
				claimsParameter: {
					title: 'The claims parameter',
					body: 'Per-request claim selection, including essential claims and the acr request.'
				},
				rpInitiatedLogout: {
					title: 'RP-initiated logout',
					body: 'End the session from the client, with a confirmation step so a link cannot log a user out silently. On by default.'
				},
				backchannelLogout: {
					title: 'Backchannel logout',
					body: 'Notify every client of a session that ended, server to server.'
				}
			}
		},
		security: {
			heading: 'Security',
			title: 'Sender-constrained tokens, and defences that are already on.',
			blurb:
				'The banking-grade profiles are flags, not editions. The rest of this list is on from the first start.',
			items: {
				dpop: {
					title: 'DPoP',
					body: 'Sender-constrained access and refresh tokens, including server nonces, so a stolen token is not enough.'
				},
				mtls: {
					title: 'mTLS client authentication',
					body: 'Client certificates for authentication and certificate-bound access tokens.'
				},
				fapi: {
					title: 'FAPI profile behaviours',
					body: 'The stricter checks the Financial-grade API profiles require, as one switch.'
				},
				ipsieSl1: {
					title: 'IPSIE SL1 enterprise profile',
					body: 'One switch applies provider rules from the OpenID Foundation’s draft enterprise profile: preregistered clients only, DPoP-bound tokens, PS256, ES256 or EdDSA signatures and binding authentication levels. A readiness check lists what stands in the way before you switch.'
				},
				assertionAudience: {
					title: 'Issuer-only client assertion audience',
					body: 'The server accepts a client assertion only when the assertion names this server’s issuer as its sole audience. The rule closes the audience-injection attack that rfc7523bis answers. The rule is off by default until rfc7523bis becomes an RFC.'
				},
				encryption: {
					title: 'Token and response encryption',
					body: 'Encrypted ID tokens, UserInfo and JARM responses using the client’s registered keys.'
				},
				totp: {
					title: 'TOTP second factor',
					body: 'Per-project time-based one-time passwords, optionally enforced for the admin console.'
				},
				pairwise: {
					title: 'Pairwise subject identifiers',
					body: 'A different sub per sector, salted from the database, so two relying parties cannot correlate a user.'
				},
				bruteForce: {
					title: 'Sign-in brute-force throttle',
					body: 'Persisted per-identity failure counters with escalating lockouts. A throttled refusal looks exactly like a wrong password.'
				},
				rateLimit: {
					title: 'Per-origin rate limiting',
					body: 'Tiered by route class and on by default, with the trusted-proxy hop configurable.'
				},
				cors: {
					title: 'CORS closed by data',
					body: 'An origin is readable only if the calling application lists it among its own allowed origins. No wildcard setting opens it.'
				},
				headers: {
					title: 'Security headers',
					body: 'HSTS, Permissions-Policy, framing and content-type protections on every response.'
				},
				scopes: {
					title: 'Scope-based access control',
					body: 'Per-client scope enforcement, checked at the authorization endpoint and again at the token endpoint.'
				}
			}
		},
		administration: {
			heading: 'Administration',
			title: 'One management API, three front doors.',
			blurb:
				'The console, the HTTP API and the MCP tools dispatch into the same routes, so the checks and the audit write cannot drift.',
			items: {
				console: {
					title: 'Administration console',
					body: 'Projects with their applications and APIs, administrators and their teams, end users, upstream providers, SCIM connections, settings, SMTP and signing keys. Every screen has an address. A change that could lock people out or break applications first shows who it affects and how many, and applies only once you confirm.'
				},
				audit: {
					title: 'Append-only audit trail',
					body: 'Every state-changing admin action records actor, action, target and time. The entry is written before the mutation, and the store has no update or delete path.'
				},
				usage: {
					title: 'Monthly active users per project',
					body: 'Each project counts the people it issued tokens to, once per UTC month and day, split into local sign-in, upstream sign-in, renewal and directory provisioning. A closed month never changes, and the history outlives the people and the project. The Usage page shows every project beside the team that owns it, so whoever runs an instance for other teams or customers can see who used how much.'
				},
				plans: {
					title: 'Plans for a shared instance',
					body: 'A plan is a named set of limits on a project: monthly active users, applications, APIs, projects per administrator, enterprise sign-in, and whether the team names its address. A limit stops only something new: nothing that exists is switched off, and nobody is refused a sign-in. At the user cap, only new self-service sign-ups pause. A super administrator edits the plans and moves projects between them. Nothing is billed.'
				},
				mcp: {
					title: 'Administration over MCP',
					body: (toolCount: number) =>
						`${toolCount} tools served to an AI agent at POST /mcp as an OAuth 2.1 protected resource. A high-consequence operation runs only after a second, confirming call.`
				},
				mcpAuthorization: {
					title: 'Authorization for your own MCP servers',
					body: 'Declare a third-party MCP server as a protected resource of a project, and FoxAuth mints tokens whose audience is exactly that resource, with no code change to FoxAuth and no restart. In a project with an address of its own, the declaration needs nothing from the resource: it can be internal, on localhost or not yet deployed. Another tenant may declare the same URL without affecting yours. Tokens are self-contained by default, so the resource verifies them against its project’s published keys without credentials of its own.'
				},
				clientIdMetadataDocument: {
					title: 'Client identity documents',
					body: 'A client_id can be an HTTPS URL that names a JSON document describing the client. The server retrieves and validates the document on demand and never stores it. The MCP authorization specification names this mechanism first for a client with no prior relationship to the server.'
				},
				registration: {
					title: 'Dynamic client registration',
					body: 'Clients register themselves, subject to the registration policy. Deprecated by the MCP specification in favour of client identity documents.'
				},
				registrationManagement: {
					title: 'Registration management',
					body: 'Read, update and delete a registration with its registration access token.'
				},
				databaseClients: {
					title: 'Database-backed clients',
					body: 'Clients live in the server’s own store, created through the console, the API, dynamic registration or the setup script. There is no static client file.'
				},
				groupOwnership: {
					title: 'Team ownership',
					body: 'Projects are owned by a team of administrators, and so is everything in them: end users, applications and APIs. Only membership of the team grants access, and membership is checked again on every request. A project moves to another team with everything it holds, in one step.'
				},
				bucketAddress: {
					title: 'A project addressed by a path, a subdomain or a host',
					body: 'Each project is its own issuer, with its own metadata and signing keys, reached at exactly one address: a path beneath the server, a subdomain of it, or a hostname of its own. A subdomain or a hostname lets the browser isolate that project’s sign-in cookie by origin and publishes one metadata location instead of two. Subdomains cost one wildcard DNS record and certificate for the whole instance; a hostname costs a record and a certificate of its own. Changing an address is its own operation: it shows you which clients it will break before it breaks them.'
				},
				bucketDeletion: {
					title: 'Deleting a project can be undone',
					body: 'Delete switches a project off at once and destroys it 30 days later. Until then nothing in it is destroyed, and Restore brings it back with every session and refresh token still valid.'
				},
				selfService: {
					title: 'End-user self-service',
					body: 'Email verification and password reset per project, each with attempt caps, cooldowns and single-use links. An address counts as verified, and applications are told email_verified: true, only once it is proven: from the mailbox, by a trusted identity provider or directory, or by an administrator who marks it.'
				},
				endUsers: {
					title: 'End-user administration',
					body: 'Invite a person to set their own password, mark an address verified, or sign someone out of one application and leave the others. Up to 100 people can be deactivated, activated, signed out or deleted at once, each with an audit entry of their own.'
				},
				federation: {
					title: 'Sign in with Google, Microsoft, Apple or GitHub',
					body: 'Connect one by name and the console shows you what to do at the provider and the exact callback address to register; you supply only the values it issues. Any other OIDC provider can be configured by hand. Per project, so each tenant uses its own application. Try sign-in shows what a real sign-in would do before anyone relies on the provider, and the callback refuses an answer from an issuer other than the one the sign-in started with. Administrators can sign in to the console through your organisation’s provider too.'
				},
				upstreamLogout: {
					title: 'Sign-out at an upstream provider ends sessions here',
					body: 'When a person signs out at Keycloak, Auth0 or Ping, the provider sends a logout token. The sessions here that began with that provider session end, and the applications they reached are told. Offline access is kept, because a sign-out is not a compromise. Each provider is opted in on its own, and the token must be signed with the provider’s published keys.'
				},
				globalTokenRevocation: {
					title: 'Okta Universal Logout',
					body: 'An opted-in provider sends one signed request, and everything the person holds here ends: sessions, refresh tokens, and every access token the server can revoke. The account stays active, so the person can sign in again. The feature follows an Internet-Draft that has expired, so it has a flag of its own.'
				},
				scim: {
					title: 'SCIM 2.0 provisioning',
					body: 'Microsoft Entra ID, Okta or any SCIM 2.0 directory creates, updates and removes a project’s users and groups. A removal of many people at once can be held for review instead of applied, and a replaced secret or static token keeps working until the directory has switched to the new one.'
				},
				signingKeys: {
					title: 'Signing key management',
					body: 'Each project with an address of its own signs with keys of its own, published at its own jwks_uri, so one tenant’s token never verifies at another’s resource server. The team that owns the project rotates them in one step. A new key is published before it may sign, and a retired one stays published until its tokens expire. The team can also revoke a compromised key at once, so nothing it signed verifies any more. The instance key set stays a super administrator’s.'
				}
			}
		},
		extensibility: {
			heading: 'Extensibility',
			title: 'Change behaviour without forking.',
			blurb:
				'Named seams and one adapter interface, so your changes should survive an upgrade.',
			items: {
				overrideSeams: {
					title: '31 override seams',
					body: 'Account lookup, interaction policy, refresh-token rotation, resource resolution, pairwise identifiers, RAR handling and more, replaced at call time.'
				},
				storage: {
					title: 'Pluggable storage',
					body: (backends: string) =>
						`Every persisted model goes through one adapter interface. ${backends} implementations ship; one connection string picks which.`
				},
				mountable: {
					title: 'Mountable Elysia app',
					body: 'Import the app and mount it in your own Bun service. There is no init step: importing the app is what boots it.'
				},
				loginUi: {
					title: 'Built-in login and consent UI',
					body: 'React and Ant Design screens in English, Russian and Simplified Chinese, light or dark with the device. The consent page says who is asking and lets people choose what an app gets, and a connected-apps page lets them take it back. Theme the screens, or replace them through the interaction policy.'
				}
			}
		},
		operations: {
			heading: 'Operations',
			title: 'Ship it, and find out why a request failed.',
			blurb:
				'A container image to ship, a record of server faults, optional Sentry reporting, and references generated from the code.',
			items: {
				containerImage: {
					title: 'Published container image',
					body: 'ghcr.io/redfox-soft/oauth-server-ts, tagged per release and latest, with a Compose file that provisions the schema.'
				},
				errorStore: {
					title: 'Server error store',
					body: 'Internal faults are recorded and readable in the console. Routine client rejections are correct behaviour and never appear.'
				},
				sentry: {
					title: 'Optional Sentry reporting',
					body: 'Reporting sits off the request path entirely: a fault reaches it only after it is classified as a defect, so responses are unchanged.'
				},
				settings: {
					title: 'Settings you can read',
					body: 'Every server-wide setting is documented with its type, default and consequence, and edited in the console.'
				},
				machineReadable: {
					title: 'Machine-readable reference',
					body: 'The endpoint, settings, admin API, MCP tool and environment references are generated from the code.'
				}
			}
		}
	},
	/* The last entry of the shipped-backends list; the database names before it are product names. */
	inMemoryBackend: 'in-memory',
	screenshots: {
		auditTrail: {
			alt: 'The admin audit trail listing actor, action, target and timestamp for each change.',
			caption:
				'The audit trail. Entries are written before the mutation and the store exposes no update or delete, so an entry cannot be altered after the fact.'
		},
		settings: {
			alt: 'The admin console settings pane showing the grant-type flags and their current values.',
			caption:
				'Settings, one pane per domain. A flag here is the same key the Reference documents; changes are validated as a whole configuration before they are saved.'
		}
	},
	next: {
		eyebrow: 'Next',
		heading: 'Compare it with what you run today.',
		lead: 'We keep a factual, dated comparison with the servers teams usually weigh FoxAuth against.',
		allComparisons: 'All comparisons',
		pricing: 'Pricing'
	}
};
