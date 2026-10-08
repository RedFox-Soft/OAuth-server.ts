/*
 * Card text is keyed by a stable name rather than listed in order, so the view can attach a card's
 * flag and spec link to its text by name; a reordering on one side cannot pair a body with the
 * wrong setting.
 */
export default {
	title: 'Features',
	description:
		'Every grant, profile and control OAuth-server.ts implements: OAuth 2.1 with PKCE, DPoP, PAR, FAPI, CIBA and mTLS, an audited console, and OAuth for MCP servers.',
	hero: {
		eyebrow: 'Features',
		heading: 'Everything is in the box. Most of it is switched off.',
		lead: 'FoxAuth ships one server with no feature editions. Authorization Code with PKCE and OpenID Connect run from the first start, and most of the rest wait behind a named flag. In practice your attack surface is the set of features you actually asked for. Each card says whether its feature is on from the first start or waits for its flag.',
		flags:
			'Each flag below links to its entry in the Settings reference, which is generated from the code and names the default and the consequence.',
		getStarted: 'Get started',
		settingsReference: 'Settings reference'
	},
	groups: {
		protocol: {
			heading: 'Protocol',
			title: 'Every grant an OAuth 2.1 client can ask for.',
			blurb:
				'The grants and endpoints. Authorization Code with PKCE and OpenID Connect are always on; most of the rest wait for a flag.',
			items: {
				pkce: {
					title: 'Authorization Code with PKCE',
					body: 'PKCE is mandatory for every client, public or confidential, as OAuth 2.1 requires. Redirect URIs match exactly.'
				},
				oidc: {
					title: 'OpenID Connect Core 1.0',
					body: 'ID tokens, the UserInfo endpoint and discovery, with the standard claim set and pairwise subjects.'
				},
				issuerIdentification: {
					title: 'Issuer identification',
					body: 'Every authorization response carries iss, so a client cannot be tricked into accepting another issuer’s code.'
				},
				resourceIndicators: {
					title: 'Resource Indicators',
					body: 'Audience-restrict a token with the resource parameter, and validate it at the resource server. On by default.'
				},
				clientCredentials: {
					title: 'Client Credentials grant',
					body: 'Machine-to-machine tokens with no end-user, scoped per client.'
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
			title: 'Sender constraint, and defences that are already on.',
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
				encryption: {
					title: 'Token and response encryption',
					body: 'Encrypted ID tokens, UserInfo and JARM responses using the client’s registered keys.'
				},
				totp: {
					title: 'TOTP second factor',
					body: 'Per-bucket time-based one-time passwords, optionally enforced for the admin console.'
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
					body: 'An origin is readable only if the project that owns the calling client lists it. No wildcard setting opens it.'
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
					body: 'Projects, OAuth clients, administrators, user buckets, end-users, upstream providers, settings, SMTP and signing keys.'
				},
				audit: {
					title: 'Append-only audit trail',
					body: 'Every state-changing admin action records actor, action, target and time. The entry is written before the mutation, and the store has no update or delete path.'
				},
				mcp: {
					title: 'Administration over MCP',
					body: (toolCount: number) =>
						`${toolCount} tools served to an AI agent at POST /mcp as an OAuth 2.1 protected resource, with two-call confirmation on high-consequence operations.`
				},
				mcpAuthorization: {
					title: 'Authorization for your own MCP servers',
					body: 'Declare a third-party MCP server as a protected resource of a project and this server mints tokens whose audience is exactly that resource, with no code change here and no restart. In a bucket with an address of its own the declaration needs nothing from the resource — it can be internal, on localhost or not yet deployed — and another tenant may declare the same URL without affecting yours. Tokens are self-contained by default, so the resource verifies them against its bucket’s published keys without credentials of its own.'
				},
				clientIdMetadataDocument: {
					title: 'Client identity documents',
					body: 'A client_id that is an HTTPS URL naming a JSON document describing the client, retrieved and validated on demand and never stored — the mechanism the MCP authorization specification names first for a client with no prior relationship.'
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
					title: 'Group ownership',
					body: 'Projects and user buckets are owned by a group. Nothing but membership grants access, and it is re-resolved on every request.'
				},
				bucketAddress: {
					title: 'A bucket addressed by a path or a host',
					body: 'Each user bucket is its own issuer, with its own metadata and signing keys, reached at a path beneath the server or at a hostname of its own — one or the other, never both. A hostname lets the browser isolate that bucket’s sign-in cookie by origin and publishes one metadata location instead of two; it costs a DNS record and a certificate you provide. Changing an address is its own operation: it shows you which clients it will break before it breaks them.'
				},
				selfService: {
					title: 'End-user self-service',
					body: 'Email verification and password reset per bucket, each with attempt caps, cooldowns and single-use links.'
				},
				federation: {
					title: 'Sign in with Google, Microsoft, Apple or GitHub',
					body: 'Connect one by name and the console shows you what to do at the provider and the exact callback address to register; you supply only the values it issues. Any other OIDC provider can be configured by hand. Per user bucket, so each tenant uses its own application.'
				},
				signingKeys: {
					title: 'Signing key management',
					body: 'Each bucket with an address of its own signs with keys of its own, published at its own jwks_uri, so one tenant’s token never verifies at another’s resource server. The bucket’s owning group rotates them — a new key is published before it may sign, and a retired one stays published until its tokens expire — while the instance key set stays a super administrator’s.'
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
					body: 'Import the app and mount it in your own Bun service. There is no init step — importing is what boots it.'
				},
				loginUi: {
					title: 'Built-in login and consent UI',
					body: 'React and Ant Design screens you can theme, or replace through the interaction policy.'
				}
			}
		},
		operations: {
			heading: 'Operations',
			title: 'What you need when something is wrong.',
			blurb: 'Ship it, watch it, and find out why a request failed.',
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
					body: 'The endpoint, settings, admin API, MCP tool and environment references are generated from the code itself.'
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
		lead: 'We keep a factual, dated comparison against the servers teams usually weigh this against.',
		allComparisons: 'All comparisons',
		pricing: 'Pricing'
	}
};
