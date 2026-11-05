/*
 * The proxy configuration an administrator pastes for an app behind a proxy (specs/122 R1, R9, R14).
 *
 * One source for the console's Connect step and the website's recipe page, so the two can never show different
 * text (FR-034). Import-free beyond the URL global: the console bundles it and the docs export reads it.
 *
 * Every recipe does two things the check relies on. It removes any `X-Auth-*` header the browser sent before the
 * request reaches the app, since a proxy that only overwrites the headers it receives would let a forged identity
 * through on a path whose answer leaves one empty. And it passes the original host, path and method, which the
 * check refuses to guess.
 */

export type ProxyKind = 'caddy' | 'traefik' | 'nginx';

export const PROXY_KINDS: readonly ProxyKind[] = ['caddy', 'traefik', 'nginx'];

/* What the check answers on success and the app receives. */
export const IDENTITY_HEADERS = [
	'X-Auth-User',
	'X-Auth-Email',
	'X-Auth-Groups',
	'X-Auth-Assertion',
	'X-Auth-Reason'
] as const;

/*
 * What the API check answers on success and an API behind the proxy receives (specs/123 R8): the token's `sub`, its
 * client and its scopes. The `Authorization` header itself is passed on untouched, for a server that exchanges it.
 */
export const API_IDENTITY_HEADERS = [
	'X-Auth-Subject',
	'X-Auth-Client',
	'X-Auth-Scope',
	'X-Auth-Reason'
] as const;

export interface RecipeValues {
	/* The check's address, e.g. `https://auth.example.com/acme/verify/<appId>`. */
	verifyUrl: string;
	/* The app's canonical address, e.g. `https://app.example.com`; for an API, its identifier. */
	appAddress: string;
	/* An app people sign in to (specs/122), or an API whose tokens the proxy checks (specs/123). */
	target?: 'app' | 'api';
}

/* Where the app itself listens; the operator replaces it. */
const UPSTREAM = 'http://127.0.0.1:8080';

export function recipeFor(kind: ProxyKind, values: RecipeValues): string {
	if (values.target === 'api') {
		switch (kind) {
			case 'caddy':
				return apiCaddy(values);
			case 'traefik':
				return apiTraefik(values);
			case 'nginx':
				return apiNginx(values);
		}
	}
	switch (kind) {
		case 'caddy':
			return caddy(values);
		case 'traefik':
			return traefik(values);
		case 'nginx':
			return nginx(values);
	}
}

function parts({ verifyUrl, appAddress }: RecipeValues) {
	const verify = new URL(verifyUrl);
	const app = new URL(appAddress);
	return {
		verifyOrigin: verify.origin,
		verifyHost: verify.host,
		verifyPath: verify.pathname,
		appHost: app.hostname,
		appHostPort: app.host,
		appPort: app.port
	};
}

/*
 * `route` keeps the written order: by default Caddy runs `forward_auth` before `request_header`, which would delete
 * the headers the check just set.
 */
function caddy(values: RecipeValues): string {
	const { verifyOrigin, verifyPath, appHostPort } = parts(values);
	return `${appHostPort} {
	route {
		request_header -X-Auth-*
		forward_auth ${verifyOrigin} {
			uri ${verifyPath}
			header_up Host {upstream_hostport}
			copy_headers ${IDENTITY_HEADERS.join(' ')}
		}
		reverse_proxy ${UPSTREAM.replace('http://', '')}
	}
}
`;
}

/*
 * `authResponseHeadersRegex` strips every matching header of the request before copying the check's. Traefik
 * prefixes a relative `Location` with the check's own host unless told to keep it.
 */
function traefik(values: RecipeValues): string {
	const { appHost } = parts(values);
	return `http:
  middlewares:
    foxauth:
      forwardAuth:
        address: "${values.verifyUrl}"
        trustForwardHeader: false
        authResponseHeadersRegex: "^X-Auth-"
        preserveLocationHeader: true
  routers:
    app:
      rule: "Host(\`${appHost}\`)"
      entryPoints:
        - websecure
      middlewares:
        - foxauth
      service: app
      tls: {}
  services:
    app:
      loadBalancer:
        servers:
          - url: "${UPSTREAM}"
`;
}

/*
 * nginx's `auth_request` understands only 2xx, 401 and 403, so its check asks for status codes only, and the
 * redirects and pages come from a second call made for the error page and for the reserved `/_foxauth/` paths.
 * A named location cannot carry a URI in `proxy_pass`, hence `rewrite … break`; the trailing `?` keeps the
 * browser's own query (which could say `mode=status`) off the check's address. `proxy_redirect off` keeps
 * nginx from rewriting the sign-in redirect onto the app's host. A header set to an empty value is not sent, and
 * a header named by `proxy_set_header` is never copied from the browser, so the five lines also clear forgeries.
 */
function nginx(values: RecipeValues): string {
	const { verifyOrigin, verifyHost, verifyPath, appHost, appPort } =
		parts(values);
	const forwardedHost = appPort ? '$host:$server_port' : '$host';
	const forwarded = `proxy_set_header X-Forwarded-Host ${forwardedHost};
		proxy_set_header X-Forwarded-Uri $request_uri;
		proxy_set_header X-Forwarded-Method $request_method;
		proxy_set_header Host ${verifyHost};
		proxy_ssl_server_name on;
		proxy_pass_request_body off;
		proxy_set_header Content-Length "";`;
	const relay = `rewrite ^ ${verifyPath}? break;
		proxy_pass ${verifyOrigin};
		proxy_redirect off;
		${forwarded}`;
	const copied = IDENTITY_HEADERS.map(
		(name) =>
			`auth_request_set $foxauth_${variable(name)} $upstream_http_${variable(name)};`
	).join('\n\t\t');
	const passed = IDENTITY_HEADERS.map(
		(name) => `proxy_set_header ${name} $foxauth_${variable(name)};`
	).join('\n\t\t');
	return `server {
	listen ${appPort || '443'} ssl;
	server_name ${appHost};
	# ssl_certificate and ssl_certificate_key for ${appHost}

	location / {
		auth_request /_foxauth_check;
		${copied}
		error_page 401 403 = @foxauth;

		${passed}
		proxy_set_header Host $host;
		proxy_pass ${UPSTREAM};
	}

	location = /_foxauth_check {
		internal;
		proxy_pass ${verifyOrigin}${verifyPath}?mode=status;
		${forwarded}
	}

	location /_foxauth/ {
		${relay}
	}

	location @foxauth {
		${relay}
	}
}
`;
}

function variable(header: string): string {
	return header.toLowerCase().replace(/-/g, '_');
}

/*
 * The same order as an app's: strip any `X-Auth-*` the client sent, ask the check, copy what it answers. No
 * `/_foxauth/` relay: an API is never sent to a sign-in, and every refusal is the check's own answer, passed back
 * with its `WWW-Authenticate` by `forward_auth` on any status that is not 2xx.
 */
function apiCaddy(values: RecipeValues): string {
	const { verifyOrigin, verifyPath, appHostPort } = parts(values);
	return `${appHostPort} {
	route {
		request_header -X-Auth-*
		forward_auth ${verifyOrigin} {
			uri ${verifyPath}
			header_up Host {upstream_hostport}
			copy_headers ${API_IDENTITY_HEADERS.join(' ')}
		}
		reverse_proxy ${UPSTREAM.replace('http://', '')}
	}
}
`;
}

/* Traefik returns the check's whole answer, headers included, for any status that is not 2xx. */
function apiTraefik(values: RecipeValues): string {
	const { appHost } = parts(values);
	return `http:
  middlewares:
    foxauth:
      forwardAuth:
        address: "${values.verifyUrl}"
        trustForwardHeader: false
        authResponseHeadersRegex: "^X-Auth-"
  routers:
    api:
      rule: "Host(\`${appHost}\`)"
      entryPoints:
        - websecure
      middlewares:
        - foxauth
      service: api
      tls: {}
  services:
    api:
      loadBalancer:
        servers:
          - url: "${UPSTREAM}"
`;
}

/*
 * nginx copies the check's `WWW-Authenticate` to the client by itself only on a 401. A missing scope is a 403 whose
 * challenge says which scopes to ask for, so the map re-adds it on a 403 and on nothing else (an empty value is not
 * sent); being a `map`, it sits in the http context, which a file in conf.d already is.
 */
function apiNginx(values: RecipeValues): string {
	const { verifyOrigin, verifyHost, verifyPath, appHost, appPort } =
		parts(values);
	const forwardedHost = appPort ? '$host:$server_port' : '$host';
	const copied = API_IDENTITY_HEADERS.map(
		(name) =>
			`auth_request_set $foxauth_${variable(name)} $upstream_http_${variable(name)};`
	).join('\n\t\t');
	const passed = API_IDENTITY_HEADERS.map(
		(name) => `proxy_set_header ${name} $foxauth_${variable(name)};`
	).join('\n\t\t');
	return `map $status $foxauth_scope_challenge {
	403 $foxauth_www_authenticate;
	default "";
}

server {
	listen ${appPort || '443'} ssl;
	server_name ${appHost};
	# ssl_certificate and ssl_certificate_key for ${appHost}

	location / {
		auth_request /_foxauth_check;
		${copied}
		auth_request_set $foxauth_www_authenticate $upstream_http_www_authenticate;
		add_header WWW-Authenticate $foxauth_scope_challenge always;

		${passed}
		proxy_set_header Host $host;
		proxy_pass ${UPSTREAM};
	}

	location = /_foxauth_check {
		internal;
		proxy_pass ${verifyOrigin}${verifyPath};
		proxy_set_header X-Forwarded-Host ${forwardedHost};
		proxy_set_header X-Forwarded-Uri $request_uri;
		proxy_set_header X-Forwarded-Method $request_method;
		proxy_set_header Host ${verifyHost};
		proxy_ssl_server_name on;
		proxy_pass_request_body off;
		proxy_set_header Content-Length "";
	}
}
`;
}
