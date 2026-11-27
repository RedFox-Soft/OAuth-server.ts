import { esc } from '../html/escape.js';
import { page } from '../interactions/plainPage.js';
import {
	formatAgo,
	formatDate,
	formatDateTime,
	formatList
} from '../i18n/format.js';
import type { Language } from '../i18n/languages.js';
import { html, htmlWith, plural, text } from '../i18n/message.js';
import {
	ACCOUNT_TEXTS,
	type AccountTexts
} from '../i18n/texts/account/index.js';
import { CONSENT_TEXTS } from '../i18n/texts/consent/index.js';
import type {
	ConsentGroup,
	ConsentItem,
	RarBlock
} from '../interactions/consentView.js';
import type { ApplicationRow } from './view.js';
import {
	BROWSER_NAMES,
	SYSTEM_NAMES,
	countryWords
} from '../person_activity/sign_in_words.js';
import type { OwnSignIn, OwnSignInsView } from '../person_activity/own.js';
import { foxVar } from '../html/theme/palette.js';

/*
 * The connected-applications page as markup (specs/095). The plain, script-free family: every step — the list,
 * the confirmation, the removal — is a link or a form, so all of it works with scripts off (R10). Every value
 * reaching the markup goes through `esc`; the sentences come from the catalog.
 *
 * Contrast: every colour is a palette role (lib/html/theme/palette.ts), held to WCAG AA in the light and the
 * dark scheme by its test. Every control is at least 24 px tall, and none removes the browser's focus ring.
 */

const MUTED = `color:${foxVar('text-secondary')};`;
const LINK = `color:${foxVar('link')}; display:inline-block; min-height:24px; line-height:24px;`;
const DANGER_LINK = `color:${foxVar('danger-strong')}; display:inline-block; min-height:24px; line-height:24px;`;
const BUTTON = `background:${foxVar('danger-solid')}; color:${foxVar('on-danger')}; border:0; border-radius:6px; padding:0 16px; min-height:32px; font-size:14px; cursor:pointer;`;

export interface PageFrame {
	service: string;
	logoSrc: string;
	/* The page's own path: links and the form stay on whatever origin served it. */
	path: string;
	signOutHref: string;
	email: string;
	language: Language;
}

function header(frame: PageFrame): string {
	return `<div style="display:flex; align-items:center; gap:8px; margin-bottom:16px; ${MUTED}"><img src="${esc(frame.logoSrc)}" alt="" width="24" height="24"/><span>${esc(frame.service)}</span></div>`;
}

function stamp(date: Date, language: Language): string {
	const iso = date.toISOString();
	const shown = text(ACCOUNT_TEXTS[language].dateTime, {
		dateTime: formatDateTime(language, date.getTime())
	});
	return `<time datetime="${esc(iso)}">${esc(shown)}</time>`;
}

function capitalised(text: string): string {
	return text.charAt(0).toUpperCase() + text.slice(1);
}

function itemText(item: ConsentItem, language: Language): string | undefined {
	if (item.category)
		return capitalised(CONSENT_TEXTS[language].categories[item.category]);
	return item.text;
}

function codes(list: readonly string[]): string {
	return list.map((c) => `<code>${esc(c)}</code>`).join(', ');
}

function rarList(blocks: readonly RarBlock[], language: Language): string {
	return blocks
		.map(
			(block) =>
				`<li>${esc(block.label)}${block.fields.length ? `<ul>${block.fields.map((f) => `<li>${esc(CONSENT_TEXTS[language].rarFields[f.field])}: ${esc(f.values)}</li>`).join('')}</ul>` : ''}</li>`
		)
		.join('');
}

function groupList(group: ConsentGroup, language: Language): string {
	const lines: string[] = [];
	for (const item of group.items) {
		const line = itemText(item, language);
		lines.push(`<li>${line ? esc(line) : codes(item.codes)}</li>`);
	}
	for (const block of group.resources) {
		const inner = block.items
			.map((item) => {
				const line = itemText(item, language);
				return `<li>${line ? esc(line) : codes(item.codes)}</li>`;
			})
			.join('');
		lines.push(
			`<li>${esc(CONSENT_TEXTS[language].resource.heading)} ${esc(block.name ?? block.host)}<ul>${inner}</ul></li>`
		);
	}
	const rar = rarList(group.rar, language);
	return lines.length || rar
		? `<ul style="margin:4px 0 8px; padding-left:20px;">${lines.join('')}${rar}</ul>`
		: '';
}

function technicalNames(row: ApplicationRow, T: AccountTexts): string {
	const all = new Set<string>();
	for (const group of [row.groups.see, row.groups.act]) {
		for (const item of group.items) item.codes.forEach((c) => all.add(c));
		for (const block of group.resources)
			for (const item of block.items) item.codes.forEach((c) => all.add(c));
	}
	if (!all.size) return '';
	return `<details style="margin:4px 0;"><summary style="${LINK} cursor:pointer;">${esc(T.technicalNames)}</summary><p style="${MUTED} margin:4px 0;">${codes([...all])}</p></details>`;
}

function permissions(
	row: ApplicationRow,
	service: string,
	language: Language
): string {
	const T = ACCOUNT_TEXTS[language];
	if (row.trusted) {
		return `<p style="margin:8px 0;">${html(T.trusted, { service })}</p>`;
	}
	const parts: string[] = [];
	const { see, act, other } = row.groups;
	const sections: Array<[string, ConsentGroup]> = [
		[T.canSee, see],
		[T.canDo, act],
		[T.otherAccess, other]
	];
	for (const [heading, group] of sections) {
		const list = groupList(group, language);
		if (list) {
			parts.push(
				`<h3 style="font-size:14px; margin:12px 0 0;">${esc(heading)}</h3>${list}`
			);
		}
	}
	if (row.confirmsIdentity) {
		parts.push(`<p style="margin:8px 0;">${esc(T.confirmIdentity)}</p>`);
	}
	return parts.join('') + technicalNames(row, T);
}

function logoTile(row: ApplicationRow): string {
	if (!row.logo) return '';
	return `<span style="flex:none; width:40px; height:40px; background:${foxVar('logo-plate')}; border:1px solid ${foxVar('logo-plate-border')}; border-radius:8px; display:flex; align-items:center; justify-content:center;"><img src="${esc(row.logo)}" alt="${esc(row.name)}" width="32" height="32" style="object-fit:contain; display:block;"/></span>`;
}

function where(row: ApplicationRow, language: Language): string {
	const T = ACCOUNT_TEXTS[language];
	if (!row.hosts.length) return row.onDevice ? esc(T.onThisDevice) : '';
	const hosts = row.hosts.join(', ');
	return row.moreHosts > 0
		? html(plural(T.signsInAtMore, row.moreHosts, language), {
				hosts,
				count: row.moreHosts
			})
		: html(T.signsInAt, { hosts });
}

function section(row: ApplicationRow, index: number, frame: PageFrame): string {
	const { language } = frame;
	const T = ACCOUNT_TEXTS[language];
	const id = `app-${index}`;
	const whereLine = where(row, language);
	const revokeHref = `${frame.path}?revoke=${encodeURIComponent(row.clientId)}`;
	return `<section aria-labelledby="${id}" style="border-top:1px solid ${foxVar('box-border')}; padding:16px 0;">
<div style="display:flex; gap:12px; align-items:flex-start;">${logoTile(row)}<div style="min-width:0; flex:1;"><h2 id="${id}" style="font-size:18px; margin:0; overflow-wrap:anywhere;">${esc(row.name)}</h2>${whereLine ? `<p style="${MUTED} margin:4px 0 0; overflow-wrap:anywhere;">${whereLine}</p>` : ''}</div></div>
${permissions(row, frame.service, language)}
<p style="${MUTED} margin:8px 0 0;">${htmlWith(T.given, { date: stamp(row.givenAt, language) })}${row.lastTokenAt ? `<br/>${htmlWith(T.lastToken, { date: stamp(row.lastTokenAt, language) })}` : ''}</p>
${row.keepsAccess ? `<p style="margin:8px 0 0;"><strong>${esc(T.keepsAccess)}</strong></p>` : ''}
<p style="margin:8px 0 0;"><a href="${esc(revokeHref)}" style="${DANGER_LINK}">${esc(T.remove)}<span style="position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0);">: ${esc(row.name)}</span></a></p>
</section>`;
}

export function listPage(
	frame: PageFrame,
	rows: readonly ApplicationRow[],
	notice?: string,
	/* The connected-services page (specs/117), linked only where the project offers a service to connect. */
	servicesHref?: string,
	/* The two-step verification page (specs/126), on every project. */
	securityHref?: string,
	/* The person's recent sign-ins (specs/135), on every project. */
	signInsHref?: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const services = `${
		servicesHref
			? ` · <a href="${esc(servicesHref)}" style="${LINK}">${esc(T.servicesLink)}</a>`
			: ''
	}${
		securityHref
			? ` · <a href="${esc(securityHref)}" style="${LINK}">${esc(T.securityLink)}</a>`
			: ''
	}${
		signInsHref
			? ` · <a href="${esc(signInsHref)}" style="${LINK}">${esc(T.signInsLink)}</a>`
			: ''
	}`;
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.title)}</h1>
<p style="margin:0 0 8px; overflow-wrap:anywhere;">${htmlWith(T.signedInAs, { email: `<strong>${esc(frame.email)}</strong>` })}${services} · <a href="${esc(frame.signOutHref)}" style="${LINK}">${esc(T.signOut)}</a></p>
<div role="status">${notice ? `<p style="background:${foxVar('success-bg')}; border:1px solid ${foxVar('success-border')}; border-radius:6px; padding:8px 12px; margin:8px 0;">${esc(notice)}</p>` : ''}</div>
${rows.length ? `<p style="margin:8px 0 16px;">${esc(T.intro)}</p>${rows.map((row, i) => section(row, i, frame)).join('')}` : `<p style="margin:8px 0;">${esc(T.empty)}</p>`}`;
	return page(T.title, body, 200, { wide: true, language: frame.language });
}

export function confirmationPage(
	frame: PageFrame,
	row: ApplicationRow,
	xsrf: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px; overflow-wrap:anywhere;">${html(T.confirmTitle, { app: row.name })}</h1>
<p style="margin:8px 0;">${html(T.confirmEffect, { app: row.name })} ${esc(row.trusted ? T.confirmReturnsSilently : T.confirmAsksAgain)}</p>
<form method="post" action="${esc(frame.path)}" style="display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-top:16px;">
<input type="hidden" name="clientId" value="${esc(row.clientId)}"/>
<input type="hidden" name="xsrf" value="${esc(xsrf)}"/>
<button type="submit" style="${BUTTON}">${esc(T.remove)}</button>
<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>
</form>`;
	return page(text(T.confirmTitle, { app: row.name }), body, 200, {
		wide: true,
		language: frame.language
	});
}

/* A short page for an outcome that is not the list: an expired or abandoned sign-in, a refused request. */
export function outcomePage(
	outcome: 'refused' | 'expired' | 'notSignedIn' | 'failed',
	path: string,
	status: number,
	language: Language
): Response {
	const T = ACCOUNT_TEXTS[language];
	const title = T[`${outcome}Title`];
	return page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${esc(T[outcome])}</p><p><a href="${esc(path)}" style="${LINK}">${esc(T.tryAgain)}</a></p>`,
		status,
		{ language }
	);
}

// ---------------------------------------------------------------- connected services (specs/117)

const PRIMARY = `background:${foxVar('primary-solid')}; color:${foxVar('on-primary')}; border:0; border-radius:6px; padding:0 16px; min-height:32px; font-size:14px; cursor:pointer;`;

export interface ServiceRowView {
	id: string;
	serviceName: string;
	label: string;
	scopes: readonly string[];
	missingScopes: readonly string[];
	connectedAt: string;
	/* The sign-in provider whose sign-in connected it (specs/120), by name. */
	signedInWith?: string;
	status: 'connected' | 'needs_reconnection';
	/* The applications that may use it, and those the person could let (specs/118 R8). */
	agents: readonly { clientId: string; name: string; lastUsedAt?: number }[];
	candidates: readonly { clientId: string; name: string }[];
}

function hidden(fields: Record<string, string>): string {
	return Object.entries(fields)
		.map(
			([name, value]) =>
				`<input type="hidden" name="${esc(name)}" value="${esc(value)}"/>`
		)
		.join('');
}

/* Who may use the account, each with a Withdraw, and a form to allow one more (specs/118 FR-022, FR-022a). */
function agentsOf(row: ServiceRowView, frame: PageFrame, xsrf: string): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const listed = row.agents.length
		? `<ul style="list-style:none; padding:0; margin:4px 0 0;">${row.agents
				.map(
					(agent) =>
						`<li style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:4px 0;"><span style="overflow-wrap:anywhere;">${esc(agent.name)}</span><span style="${MUTED}">${
							agent.lastUsedAt === undefined
								? esc(T.agentNotUsed)
								: htmlWith(T.agentUsed, {
										date: stamp(
											new Date(agent.lastUsedAt * 1000),
											frame.language
										)
									})
						}</span><form method="post" action="${esc(frame.path)}" style="margin:0;">${hidden({ action: 'withdraw', connectedAccountId: row.id, clientId: agent.clientId, xsrf })}<button type="submit" style="${DANGER_LINK} background:none; border:none; padding:0; cursor:pointer;">${esc(T.withdraw)}<span style="position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0);">: ${esc(agent.name)}</span></button></form></li>`
				)
				.join('')}</ul>`
		: `<p style="${MUTED} margin:4px 0 0;">${esc(T.agentsNone)}</p>`;
	const allow = row.candidates.length
		? `<form method="post" action="${esc(frame.path)}" style="display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin:8px 0 0;">${hidden({ action: 'allow', connectedAccountId: row.id, xsrf })}<label style="display:flex; flex-wrap:wrap; gap:8px; align-items:center;">${esc(T.allowHeading)} <select name="clientId">${row.candidates
				.map(
					(candidate) =>
						`<option value="${esc(candidate.clientId)}">${esc(candidate.name)}</option>`
				)
				.join(
					''
				)}</select></label><button type="submit" style="${PRIMARY}">${esc(T.allow)}</button></form>`
		: '';
	return `<h3 style="font-size:15px; margin:12px 0 0;">${esc(T.agentsHeading)}</h3>${listed}${allow}`;
}

export interface OfferedService {
	id: string;
	displayName: string;
}

/* What the page says after an act: a sentence, and the provider's own access page where the person must act. */
export interface ServicesNotice {
	lines: readonly string[];
	manage?: { href: string; service: string } | undefined;
}

function noticeBox(
	notice: ServicesNotice | undefined,
	language: Language
): string {
	if (!notice || notice.lines.length === 0) return '';
	const T = ACCOUNT_TEXTS[language];
	const manage = notice.manage
		? `<br/><a href="${esc(notice.manage.href)}" style="${LINK}" rel="noopener noreferrer">${html(T.manageAccess, { service: notice.manage.service })}</a>`
		: '';
	return `<p style="background:${foxVar('success-bg')}; border:1px solid ${foxVar('success-border')}; border-radius:6px; padding:8px 12px; margin:8px 0;">${notice.lines.map((line) => esc(line)).join('<br/>')}${manage}</p>`;
}

function serviceRow(
	row: ServiceRowView,
	index: number,
	frame: PageFrame,
	xsrf: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const id = `service-${index}`;
	const disconnectHref = `${frame.path}?disconnect=${encodeURIComponent(row.id)}`;
	const scopes = row.scopes.length
		? `<p style="${MUTED} margin:4px 0 0; overflow-wrap:anywhere;">${htmlWith(T.scopesGranted, { scopes: codes(row.scopes) })}</p>`
		: '';
	const missing = row.missingScopes.length
		? `<p style="margin:4px 0 0; overflow-wrap:anywhere;">${htmlWith(T.scopesMissing, { scopes: codes(row.missingScopes) })}</p>`
		: '';
	const status =
		row.status === 'needs_reconnection'
			? `<p style="margin:4px 0 0;"><strong>${esc(T.needsReconnection)}</strong></p>`
			: '';
	return `<section aria-labelledby="${id}" style="border-top:1px solid ${foxVar('box-border')}; padding:16px 0;">
<h2 id="${id}" style="font-size:18px; margin:0; overflow-wrap:anywhere;">${esc(row.serviceName)}: ${esc(row.label)}</h2>
${scopes}${missing}${status}
<p style="${MUTED} margin:8px 0 0;">${htmlWith(T.connectedAt, { date: stamp(new Date(row.connectedAt), frame.language) })}${row.signedInWith ? `<br/>${htmlWith(T.connectedAtSignIn, { provider: row.signedInWith })}` : ''}</p>
${agentsOf(row, frame, xsrf)}
<p style="margin:8px 0 0;"><a href="${esc(disconnectHref)}" style="${DANGER_LINK}">${esc(T.disconnect)}<span style="position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0);">: ${esc(row.label)}</span></a></p>
</section>`;
}

export function servicesPage(
	frame: PageFrame,
	appsHref: string,
	rows: readonly ServiceRowView[],
	offered: readonly OfferedService[],
	xsrf: string,
	notice?: ServicesNotice,
	/* The two-step verification page (specs/126). */
	securityHref?: string,
	/* The person's recent sign-ins (specs/135). */
	signInsHref?: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const security = `${
		securityHref
			? ` · <a href="${esc(securityHref)}" style="${LINK}">${esc(T.securityLink)}</a>`
			: ''
	}${
		signInsHref
			? ` · <a href="${esc(signInsHref)}" style="${LINK}">${esc(T.signInsLink)}</a>`
			: ''
	}`;
	const connect = offered.length
		? `<h2 style="font-size:16px; margin:24px 0 8px;">${esc(T.servicesAvailable)}</h2><ul style="list-style:none; padding:0; margin:0;">${offered
				.map(
					(service) =>
						`<li style="margin:4px 0;"><a href="${esc(`${frame.path}?connect=${encodeURIComponent(service.id)}`)}" style="${LINK}">${html(T.connect, { service: service.displayName })}</a></li>`
				)
				.join('')}</ul>`
		: '';
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.servicesTitle)}</h1>
<p style="margin:0 0 8px; overflow-wrap:anywhere;">${htmlWith(T.signedInAs, { email: `<strong>${esc(frame.email)}</strong>` })} · <a href="${esc(appsHref)}" style="${LINK}">${esc(T.appsLink)}</a>${security} · <a href="${esc(frame.signOutHref)}" style="${LINK}">${esc(T.signOut)}</a></p>
<div role="status">${noticeBox(notice, frame.language)}</div>
${rows.length ? `<p style="margin:8px 0 16px;">${esc(T.servicesIntro)}</p>${rows.map((row, i) => serviceRow(row, i, frame, xsrf)).join('')}` : `<p style="margin:8px 0;">${esc(T.servicesEmpty)}</p>`}
${connect}`;
	return page(T.servicesTitle, body, 200, {
		wide: true,
		language: frame.language
	});
}

function confirmForm(
	frame: PageFrame,
	fields: Record<string, string>,
	xsrf: string,
	label: string,
	style: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const hidden = Object.entries(fields)
		.map(
			([name, value]) =>
				`<input type="hidden" name="${esc(name)}" value="${esc(value)}"/>`
		)
		.join('\n');
	return `<form method="post" action="${esc(frame.path)}" style="display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-top:16px;">
${hidden}
<input type="hidden" name="xsrf" value="${esc(xsrf)}"/>
<button type="submit" style="${style}">${esc(label)}</button>
<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>
</form>`;
}

export function connectConfirmation(
	frame: PageFrame,
	service: OfferedService,
	xsrf: string,
	/*
	 * The provider's authorization endpoint. The form posts here and is answered with a redirect there, and Chrome
	 * holds the whole chain to `form-action`, so without it the person's own Continue is blocked.
	 */
	providerAddress?: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px; overflow-wrap:anywhere;">${html(T.connectTitle, { service: service.displayName })}</h1>
<p style="margin:8px 0;">${html(T.connectEffect, { service: service.displayName })}</p>
${confirmForm(frame, { action: 'connect', serviceId: service.id }, xsrf, T.continue, PRIMARY)}`;
	return page(
		text(T.connectTitle, { service: service.displayName }),
		body,
		200,
		{
			wide: true,
			language: frame.language,
			// A confirmation is never framed, whatever origin it hands off to.
			denyFraming: true,
			...(providerAddress ? { handOffTo: providerAddress } : {})
		}
	);
}

export function disconnectConfirmation(
	frame: PageFrame,
	row: ServiceRowView,
	xsrf: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px; overflow-wrap:anywhere;">${html(T.disconnectTitle, { account: row.label })}</h1>
<p style="margin:8px 0;">${html(T.disconnectEffect, { service: row.serviceName })}</p>
${confirmForm(frame, { action: 'disconnect', connectedAccountId: row.id }, xsrf, T.disconnect, BUTTON)}`;
	return page(text(T.disconnectTitle, { account: row.label }), body, 200, {
		wide: true,
		language: frame.language
	});
}

/*
 * The connect callback's refusal, in the services page's words: the applications page's outcome speaks of signing
 * in to that page, which is not what a person returning from a provider was doing.
 */
export function connectOutcomePage(
	outcome: 'expired' | 'refused',
	path: string,
	status: number,
	language: Language
): Response {
	const T = ACCOUNT_TEXTS[language];
	const sentence = outcome === 'expired' ? T.noticeExpired : T.noticeRefused;
	return page(
		T.servicesTitle,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.servicesTitle)}</h1><p>${esc(sentence)}</p><p><a href="${esc(path)}" style="${LINK}">${esc(T.servicesLink)}</a></p>`,
		status,
		{ language }
	);
}

// ---------------------------------------------------------------- an agent's connect link (specs/119)

export interface LinkAccount {
	id: string;
	label: string;
}

export interface LinkPageView {
	act: 'connect' | 'consent' | 'reconnect';
	app: string;
	service: string;
	/* The accounts a consent offers: one named by the agent shows one button, several a checkbox each. */
	accounts: readonly LinkAccount[];
	named: boolean;
	/* The account a reconnect is for. */
	account?: LinkAccount;
	/* No other account may be connected at this service. */
	atLimit: boolean;
	/* What the provider's answer came to, when it sent the person back here. */
	notice?: string;
}

function linkForm(
	frame: PageFrame,
	xsrf: string,
	action: string,
	inner: string,
	label: string,
	style: string
): string {
	return `<form method="post" action="${esc(frame.path)}" style="margin:16px 0 0;">${hidden({ action, xsrf })}${inner}<button type="submit" style="${style}">${esc(label)}</button></form>`;
}

/*
 * The one act a link leads to, for the agent that asked (contracts/link-page.md). Every act is a button on a
 * same-origin form with the page's anti-forgery value: opening the link changes nothing.
 */
export function linkPage(
	frame: PageFrame,
	view: LinkPageView,
	xsrf: string,
	providerAddress?: string
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const vars = { app: view.app, service: view.service };
	const notice = view.notice
		? noticeBox({ lines: [view.notice, T.linkTryAgain] }, frame.language)
		: '';
	const decline = `<form method="post" action="${esc(frame.path)}" style="margin:16px 0 0;">${hidden({ action: 'decline', xsrf })}<button type="submit" style="${LINK} background:none; border:none; padding:0; cursor:pointer;">${esc(T.linkDecline)}</button></form>`;
	const another = view.atLimit
		? `<p style="margin:16px 0 0;">${html(T.linkLimit, vars)}</p>`
		: linkForm(
				frame,
				xsrf,
				'connect',
				'',
				text(T.linkConnectAnother, vars),
				PRIMARY
			);
	let title: string;
	let body: string;
	if (view.act === 'reconnect' && view.account) {
		title = text(T.linkReconnectTitle, {
			...vars,
			account: view.account.label
		});
		body = `<p style="margin:8px 0;">${html(T.linkReconnectEffect, { ...vars, account: view.account.label })}</p>${linkForm(frame, xsrf, 'connect', '', text(T.linkReconnectButton, vars), PRIMARY)}`;
	} else if (view.accounts.length === 0) {
		title = text(T.linkConnectTitle, vars);
		body = `<p style="margin:8px 0;">${html(T.linkConnectEffect, vars)}</p>${
			view.atLimit
				? `<p style="margin:16px 0 0;">${html(T.linkLimit, vars)}</p>`
				: linkForm(
						frame,
						xsrf,
						'connect',
						'',
						text(T.linkConnectButton, vars),
						PRIMARY
					)
		}`;
	} else if (view.named && view.accounts.length === 1) {
		const [account] = view.accounts;
		title = text(T.linkConsentOne, { ...vars, account: account.label });
		body = `<p style="margin:8px 0; ${MUTED}">${esc(T.linkConsentNote)}</p>${linkForm(frame, xsrf, 'allow', hidden({ connectedAccountId: account.id }), T.allow, PRIMARY)}`;
	} else {
		title = text(T.linkConsentSeveral, vars);
		const boxes = view.accounts
			.map(
				(account) =>
					`<label style="display:flex; gap:8px; align-items:center; min-height:24px; margin:4px 0; overflow-wrap:anywhere;"><input type="checkbox" name="connectedAccountId" value="${esc(account.id)}"/>${esc(account.label)}</label>`
			)
			.join('');
		body = `<p style="margin:8px 0; ${MUTED}">${esc(T.linkConsentNote)}</p>${linkForm(frame, xsrf, 'allow', boxes, T.allow, PRIMARY)}${another}`;
	}
	return page(
		title,
		`${header(frame)}<div role="status">${notice}</div><h1 style="font-size:24px; margin:0 0 8px; overflow-wrap:anywhere;">${esc(title)}</h1>${body}${decline}`,
		200,
		{
			wide: true,
			language: frame.language,
			denyFraming: true,
			...(providerAddress ? { handOffTo: providerAddress } : {})
		}
	);
}

/*
 * A link's other pages: no longer valid, someone else's, no longer possible, done, declined. None names the person
 * the link was made for or their accounts; the done pages are shown to that person only.
 */
export function linkOutcomePage(
	title: string,
	lines: readonly string[],
	status: number,
	language: Language,
	servicesHref?: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const back = servicesHref
		? `<p><a href="${esc(servicesHref)}" style="${LINK}">${esc(T.servicesLink)}</a></p>`
		: '';
	return page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1>${lines.map((line) => `<p>${esc(line)}</p>`).join('')}${back}`,
		status,
		{ language }
	);
}

// ---------------------------------------------------------------- two-step verification (specs/126)

/* The pages a person has, linked from each other; the current one as text. */
export interface AccountNav {
	apps: string;
	services?: string;
	security: string;
	signIns: string;
	current: 'apps' | 'services' | 'security' | 'signIns';
}

export function navLine(frame: PageFrame, nav: AccountNav): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const entries: [AccountNav['current'], string, string | undefined][] = [
		['apps', T.appsLink, nav.apps],
		['services', T.servicesLink, nav.services],
		['security', T.securityLink, nav.security],
		['signIns', T.signInsLink, nav.signIns]
	];
	return entries
		.filter(([, , href]) => href !== undefined)
		.map(([key, label, href]) =>
			key === nav.current
				? `<span aria-current="page">${esc(label)}</span>`
				: `<a href="${esc(href ?? '')}" style="${LINK}">${esc(label)}</a>`
		)
		.join(' · ');
}

export type SecurityView =
	| { state: 'unavailable' }
	| { state: 'noPassword' }
	| { state: 'off'; providerSession: boolean }
	| { state: 'sent'; purpose: 'enrol' | 'replace' }
	| {
			state: 'offer';
			qrSvg: string;
			key: string;
			otpauthUri: string;
			wrong: boolean;
	  }
	| {
			state: 'on';
			since: Date;
			required: boolean;
			providers: readonly string[];
			confirmOff: boolean;
	  };

export interface SecurityNotice {
	kind: 'success' | 'error';
	text: string;
}

function securityForm(
	frame: PageFrame,
	xsrf: string,
	action: string,
	label: string,
	style: string
): string {
	return `<form method="post" action="${esc(frame.path)}" style="display:inline-block; margin:8px 16px 0 0;">${hidden({ action, xsrf })}<button type="submit" style="${style}">${esc(label)}</button></form>`;
}

function securityBody(
	frame: PageFrame,
	view: SecurityView,
	xsrf: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const values = { service: frame.service, email: frame.email };
	switch (view.state) {
		case 'unavailable':
			return `<p>${html(T.securityUnavailable, values)}</p>`;
		case 'noPassword':
			return `<p>${html(T.securityNoPassword, values)}</p>`;
		case 'off':
			return [
				`<p><strong>${html(T.securityOff, values)}</strong></p>`,
				`<p>${esc(T.securityExplain)}</p>`,
				`<p>${html(T.securityNeeds, values)}</p>`,
				`<p>${html(T.securityLostPhone, values)}</p>`,
				view.providerSession
					? `<p>${esc(T.securitySignInWithPassword)}</p>`
					: '',
				securityForm(frame, xsrf, 'start', T.securityStart, PRIMARY)
			].join('');
		case 'sent':
			return [
				`<h2 style="font-size:18px; margin:16px 0 8px;">${esc(T.securitySentTitle)}</h2>`,
				`<p>${html(T.securitySent, values)}</p>`,
				securityForm(
					frame,
					xsrf,
					view.purpose === 'replace' ? 'replace' : 'start',
					T.securityResend,
					PRIMARY
				)
			].join('');
		case 'offer':
			return [
				`<h2 style="font-size:18px; margin:16px 0 8px;">${html(T.securityAddTitle, values)}</h2>`,
				`<p>${esc(T.securityScan)}</p>`,
				`<div style="display:inline-block; background:#ffffff; padding:8px; border-radius:8px; line-height:0;">${view.qrSvg}</div>`,
				`<p>${esc(T.securityKey)}<br/><code data-key="${esc(view.key)}" style="font-size:16px; letter-spacing:1px; overflow-wrap:anywhere; user-select:all;">${esc(view.key)}</code></p>`,
				`<p><a href="${esc(view.otpauthUri)}" style="${LINK}">${esc(T.securityOpenApp)}</a></p>`,
				`<p style="${MUTED}">${esc(T.securitySpare)}</p>`,
				`<form method="post" action="${esc(frame.path)}" style="margin-top:16px;">${hidden({ action: 'confirm', xsrf })}`,
				`<label for="code" style="display:block; margin-bottom:4px;">${esc(T.securityCodeLabel)}</label>`,
				`<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{6}" maxlength="6" required style="font-size:18px; letter-spacing:2px; min-height:32px; padding:0 8px; border:1px solid ${foxVar('field-border')}; border-radius:6px; width:10ch;"${view.wrong ? ' aria-invalid="true" aria-describedby="code-error"' : ''}/>`,
				view.wrong
					? `<p id="code-error" style="color:${foxVar('danger-text')}; margin:4px 0;">${esc(T.securityWrongCode)}</p>`
					: '',
				`<p style="margin-top:12px;"><button type="submit" style="${PRIMARY}">${esc(T.securityTurnOn)}</button></p>`,
				`</form>`
			].join('');
		case 'on': {
			if (view.confirmOff) {
				return [
					`<h2 style="font-size:18px; margin:16px 0 8px;">${esc(T.securityOffConfirmTitle)}</h2>`,
					`<p>${html(T.securityOffConfirm, values)}</p>`,
					securityForm(frame, xsrf, 'off', T.securityTurnOff, BUTTON),
					`<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>`
				].join('');
			}
			return [
				`<p><strong>${esc(T.securityOnTitle)}</strong></p>`,
				`<p>${htmlWith(T.securityOnSince, { date: stamp(view.since, frame.language) })}</p>`,
				`<p>${html(T.securityOnEvery, values)}</p>`,
				...view.providers.map(
					(provider) => `<p>${html(T.securityProvider, { provider })}</p>`
				),
				securityForm(frame, xsrf, 'replace', T.securityReplace, PRIMARY),
				view.required
					? `<p>${html(T.securityRequired, values)}</p>`
					: `<a href="${esc(`${frame.path}?off=1`)}" style="${DANGER_LINK}">${esc(T.securityTurnOff)}</a>`
			].join('');
		}
	}
}

// ---------------------------------------------------------------- passkeys (specs/139)

/* One passkey as its owner's page lists it: never a credential id, a key or an AAGUID. */
export interface PasskeyRowView {
	/* The record's own id, which the row's forms name: never the credential id. */
	id: string;
	name: string;
	createdAt: Date;
	lastUsedAt?: Date;
	synced: boolean;
	via:
		| 'passkey'
		| 'password_code'
		| 'password_mail'
		| 'password'
		| 'registration'
		| 'recovery'
		| 'admin_link'
		| 'federated_mail';
	/* Made for an address the project no longer has, or refused because it may have been copied: it no longer works. */
	mark?: 'oldAddress' | 'copied';
	/* Made after a password alone and not yet confirmed (specs/141): it signs in as the password does. */
	unconfirmed?: true;
	/* Created via email recovery and still within its 72-hour multi_factor ACR cap (specs/145 Q1=A). */
	recoveredUntil?: Date;
}

/*
 * What the page's script tells the browser about the person's passkeys here (specs/141 research R10): every passkey this
 * project accepts at this site, and the person's current details, for their passkey identity in this project only.
 */
export interface PasskeySignals {
	rpId: string;
	userId: string;
	accepted: readonly string[];
	name: string;
	displayName: string;
}

/* The Passkeys part of "Sign-in and security" (contracts/account-page.md), one state at a time. */
export type PasskeysView = {
	rows: readonly PasskeyRowView[];
	/* The passkey whose rename form is open (`?rename=`), and the one whose removal is to be confirmed (`?remove=`). */
	renaming?: string;
	removing?: string;
	/* A link to confirm a removal was mailed to this browser. */
	removeSent?: boolean;
	/* A strong recent sign-in: an unconfirmed passkey's row offers Confirm (specs/141 FR-017). */
	confirmable?: boolean;
	/* What the script tells the browser, and the script itself when the add form does not already load it. */
	signals?: PasskeySignals;
	script?: string;
} & (
	| { state: 'stopped' }
	| { state: 'providerOnly'; providers: readonly string[] }
	| { state: 'noMail' }
	| { state: 'unconfirmed' }
	| { state: 'full' }
	| { state: 'start' }
	| { state: 'sent' }
	| {
			state: 'add';
			/* The creation options, as JSON, for the page's one script to hand the browser. */
			options: string;
			script: string;
	  }
);

/* A plain form of the Passkeys part: its action, the page's anti-forgery value and the passkey it is about. */
function passkeyForm(
	frame: PageFrame,
	fields: Record<string, string>,
	label: string,
	style: string
): string {
	return `<form method="post" action="${esc(frame.path)}" style="display:inline-block; margin:8px 16px 0 0;">${hidden(fields)}<button type="submit" style="${style}">${esc(label)}</button></form>`;
}

/*
 * What a row offers: its rename form or its removal's confirmation when the page was opened for one, else a Rename link
 * and a Remove button. While the project does not accept passkeys a row offers only Remove: a name helps nobody choose
 * a passkey that cannot sign in.
 */
function passkeyActions(
	row: PasskeyRowView,
	frame: PageFrame,
	view: PasskeysView,
	xsrf: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const renames = view.state !== 'stopped';
	if (view.removing === row.id) {
		return [
			`<p style="margin:8px 0 0;"><strong style="overflow-wrap:anywhere;">${html(T.passkeyRemoveTitle, { name: row.name })}</strong></p>`,
			`<p style="margin:4px 0 0;">${html(T.passkeyRemoveEffect, { service: frame.service })}</p>`,
			passkeyForm(
				frame,
				{ action: 'passkey_remove', xsrf, passkey: row.id },
				T.passkeyRemoveButton,
				BUTTON
			),
			`<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>`
		].join('');
	}
	if (renames && view.renaming === row.id) {
		const field = `passkey-name-${row.id}`;
		return [
			`<form method="post" action="${esc(frame.path)}" style="margin:8px 0 0;">${hidden({ action: 'passkey_rename', xsrf, passkey: row.id })}`,
			`<label for="${esc(field)}" style="display:block; margin-bottom:4px;">${esc(T.passkeyNameLabel)}</label>`,
			`<input id="${esc(field)}" name="name" value="${esc(row.name)}" maxlength="64" required style="font-size:16px; min-height:32px; padding:0 8px; border:1px solid ${foxVar('field-border')}; border-radius:6px; width:100%; max-width:24em; box-sizing:border-box;"/>`,
			`<p style="margin:8px 0 0;"><button type="submit" style="${PRIMARY}">${esc(T.passkeySave)}</button> <a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a></p>`,
			`</form>`
		].join('');
	}
	return [
		renames
			? `<a href="${esc(`${frame.path}?rename=${encodeURIComponent(row.id)}`)}" style="${LINK} margin:8px 16px 0 0;">${esc(T.passkeyRename)}</a>`
			: '',
		passkeyForm(
			frame,
			{ action: 'passkey_remove_start', xsrf, passkey: row.id },
			T.passkeyRemove,
			BUTTON
		)
	].join('');
}

function passkeyRow(
	row: PasskeyRowView,
	frame: PageFrame,
	view: PasskeysView,
	xsrf: string
): string {
	const { language } = frame;
	const T = ACCOUNT_TEXTS[language];
	const day = (date: Date) => formatDate(language, date.getTime());
	const via = {
		passkey: T.passkeyViaPasskey,
		password_code: T.passkeyViaCode,
		password_mail: T.passkeyViaMail,
		password: T.passkeyViaPassword,
		registration: T.passkeyViaRegistration,
		recovery: T.passkeyViaRecovery,
		admin_link: T.passkeyViaAdminLink,
		federated_mail: T.passkeyViaFederatedMail
	}[row.via];
	const facts = [
		text(T.passkeyCreated, { date: day(row.createdAt) }),
		row.lastUsedAt
			? text(T.passkeyLastUsed, { date: day(row.lastUsedAt) })
			: T.passkeyNeverUsed,
		row.synced ? T.passkeySynced : T.passkeyThisDevice,
		via
	];
	const mark =
		row.mark === 'oldAddress'
			? text(T.passkeyOldAddress, { service: frame.service })
			: row.mark === 'copied'
				? T.passkeyCopied
				: undefined;
	const recoveredNotice =
		row.recoveredUntil !== undefined && !mark
			? `<br/><span style="color:${foxVar('notice-text')};">${html(T.passkeyRecoveryCapped, { date: formatDateTime(language, row.recoveredUntil.getTime()) })}</span>`
			: '';
	return [
		`<li style="margin:0 0 12px;">`,
		`<strong style="overflow-wrap:anywhere;">${esc(row.name)}</strong><br/>`,
		`<span style="${MUTED}">${facts.map((fact) => esc(fact)).join(' · ')}</span>`,
		mark
			? `<br/><span style="color:${foxVar('danger-text')};">${esc(mark)}</span>`
			: '',
		recoveredNotice,
		row.unconfirmed && !mark ? unconfirmedLine(row, frame, view, xsrf) : '',
		`<div>${passkeyActions(row, frame, view, xsrf)}</div>`,
		`</li>`
	].join('');
}

/*
 * A passkey made after a password alone (specs/141): what it is, and Confirm only after a strong recent sign-in, never
 * through a mailed link, so a link opened in the owner's browser never confirms someone else's passkey.
 */
function unconfirmedLine(
	row: PasskeyRowView,
	frame: PageFrame,
	view: PasskeysView,
	xsrf: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	return [
		`<br/><span style="color:${foxVar('notice-text')};">${esc(T.passkeyUnconfirmed)}</span>`,
		view.confirmable
			? `<div>${passkeyForm(frame, { action: 'passkey_confirm', xsrf, passkey: row.id }, T.passkeyConfirm, BUTTON)}</div>`
			: `<br/><span style="${MUTED}">${esc(T.passkeyConfirmNeeds)}</span>`
	].join('');
}

/*
 * The signals' data (specs/141 contracts/browser.md), as attributes the page's one script reads: no inline script, and
 * nothing here that the person's own page does not already show them, but their passkeys' credential ids, which the
 * browser already holds.
 */
function signalsOf(view: PasskeysView): string {
	const { signals } = view;
	if (!signals) return '';
	const script =
		view.state === 'add' || view.script === undefined
			? ''
			: `<script src="${esc(view.script)}"></script>`;
	return (
		`<div hidden data-passkey-signals data-rp-id="${esc(signals.rpId)}" data-user-id="${esc(signals.userId)}" data-accepted="${esc(JSON.stringify(signals.accepted))}" data-name="${esc(signals.name)}" data-display-name="${esc(signals.displayName)}"></div>` +
		script
	);
}

function passkeysBody(
	frame: PageFrame,
	view: PasskeysView,
	xsrf: string
): string {
	return passkeysState(frame, view, xsrf) + signalsOf(view);
}

function passkeysState(
	frame: PageFrame,
	view: PasskeysView,
	xsrf: string
): string {
	const T = ACCOUNT_TEXTS[frame.language];
	const values = { service: frame.service, email: frame.email };
	const list =
		view.rows.length > 0
			? `<ul style="list-style:none; padding:0; margin:8px 0;">${view.rows.map((row) => passkeyRow(row, frame, view, xsrf)).join('')}</ul>` +
				(view.removeSent
					? `<p>${html(T.passkeyRemoveSent, { email: frame.email })}</p>`
					: '')
			: '';
	const intro = `<p>${esc(T.passkeysExplain)}</p>`;
	switch (view.state) {
		case 'stopped':
			return list + `<p>${html(T.passkeysStopped, values)}</p>`;
		case 'providerOnly':
			return view.providers.length > 0
				? `<p>${html(T.passkeysProviderOnly, { provider: formatList(frame.language, view.providers) })}</p>`
				: `<p>${esc(T.passkeysNoPassword)}</p>`;
		case 'noMail':
			return list + `<p>${html(T.passkeysNoMail, values)}</p>`;
		case 'unconfirmed':
			return list + `<p>${esc(T.passkeysUnconfirmed)}</p>`;
		case 'full':
			return list + `<p>${esc(T.passkeysFull)}</p>`;
		case 'start':
			return (
				(list || intro) +
				securityForm(frame, xsrf, 'passkey_start', T.passkeyAdd, PRIMARY)
			);
		case 'sent':
			return [
				list,
				`<p>${html(T.passkeysSent, values)}</p>`,
				securityForm(frame, xsrf, 'passkey_start', T.securityResend, PRIMARY)
			].join('');
		case 'add':
			/*
			 * The page's one script (research R12): an external file, so no inline script; the options and the words it
			 * may show travel as attributes of the form it reads. Without scripts the button stays disabled and the
			 * sentence beside it says why; everything else on the page is a plain form.
			 */
			return [
				list || intro,
				`<form method="post" action="${esc(frame.path)}" data-passkey-add data-options="${esc(view.options)}" data-text-exists="${esc(T.passkeyExists)}" data-text-failed="${esc(T.passkeyAddFailed)}" data-text-no-uv="${esc(T.passkeyNoUserVerification)}" style="margin-top:8px;">`,
				hidden({ action: 'passkey_add', xsrf, credential: '' }),
				`<button type="button" disabled style="${PRIMARY}">${esc(T.passkeyAdd)}</button>`,
				`<p data-passkey-status role="status" style="${MUTED}">${esc(T.passkeyNeedsScript)}</p>`,
				`</form>`,
				`<script src="${esc(view.script)}"></script>`
			].join('');
	}
}

export function securityPage(
	frame: PageFrame,
	nav: AccountNav,
	view: SecurityView | undefined,
	xsrf: string,
	notice?: SecurityNotice,
	passkeys?: PasskeysView
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const box = notice
		? `<p style="background:${foxVar(notice.kind === 'success' ? 'success-bg' : 'danger-bg')}; border:1px solid ${foxVar(notice.kind === 'success' ? 'success-border' : 'danger-border')}; border-radius:6px; padding:8px 12px; margin:8px 0;">${esc(notice.text)}</p>`
		: '';
	const body = [
		header(frame),
		`<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.securityTitle)}</h1>`,
		`<p style="margin:0 0 8px; overflow-wrap:anywhere;">${htmlWith(T.signedInAs, { email: `<strong>${esc(frame.email)}</strong>` })} · <a href="${esc(frame.signOutHref)}" style="${LINK}">${esc(T.signOut)}</a></p>`,
		`<nav style="margin:0 0 8px;">${navLine(frame, nav)}</nav>`,
		`<div role="status">${box}</div>`,
		passkeys
			? `<h2 style="font-size:20px; margin:24px 0 8px;">${esc(T.passkeysTitle)}</h2>${passkeysBody(frame, passkeys, xsrf)}`
			: '',
		view
			? `<h2 style="font-size:20px; margin:24px 0 8px;">${esc(T.twoStepTitle)}</h2>${securityBody(frame, view, xsrf)}`
			: ''
	].join('');
	const response = page(T.securityTitle, body, 200, {
		wide: true,
		language: frame.language
	});
	// A page that may show a secret is never kept by a cache, whatever an intermediary does with the defaults.
	response.headers.set('cache-control', 'no-store');
	return response;
}

/* "This wasn't me" (specs/126 research R7): the confirmation, and the two outcomes. No session is needed. */
export function disownConfirmPage(
	language: Language,
	path: string,
	token: string,
	email: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	return page(
		text(T.disownTitle, { email }),
		[
			`<h1 style="font-size:20px; margin:0 0 8px; overflow-wrap:anywhere;">${html(T.disownTitle, { email })}</h1>`,
			`<p>${esc(T.disownEffect)}</p>`,
			`<form method="post" action="${esc(path)}">${hidden({ token })}<button type="submit" style="${BUTTON}">${esc(T.disownButton)}</button></form>`
		].join(''),
		200,
		{ language }
	);
}

export function disownOutcomePage(
	language: Language,
	removed: boolean,
	service: string,
	forgot: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const title = removed ? T.disownDoneTitle : T.disownNothingTitle;
	return page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${html(removed ? T.disownDone : T.disownNothing, { service, forgot })}</p>`,
		removed ? 200 : 400,
		{ language }
	);
}

/*
 * "This wasn't me" about an added passkey (specs/139 research R16). Opening the link shows only this; the form's POST
 * is the act, so a mail scanner following the link changes nothing. No session is needed.
 */
export function passkeyDisownConfirmPage(
	language: Language,
	path: string,
	fields: { token: string; project?: string },
	email: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const response = page(
		text(T.passkeyDisownTitle, { email }),
		[
			`<h1 style="font-size:20px; margin:0 0 8px; overflow-wrap:anywhere;">${html(T.passkeyDisownTitle, { email })}</h1>`,
			`<p>${esc(T.passkeyDisownEffect)}</p>`,
			`<form method="post" action="${esc(path)}">${hidden(fields)}<button type="submit" style="${BUTTON}">${esc(T.disownButton)}</button></form>`
		].join(''),
		200,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

/*
 * "Yes, this was me" about a conditional passkey (specs/141 contracts/account-page-and-mail.md). Opening the link shows
 * only this; the form's POST, with the page's anti-forgery value, is the act.
 */
export function passkeyConfirmPage(
	language: Language,
	path: string,
	fields: { token: string; xsrf: string; project?: string },
	service: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const response = page(
		T.passkeyConfirmTitle,
		[
			`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.passkeyConfirmTitle)}</h1>`,
			`<p>${html(T.passkeyConfirmEffect, { service })}</p>`,
			`<form method="post" action="${esc(path)}">${hidden(fields)}<button type="submit" style="${PRIMARY}">${esc(T.passkeyConfirmButton)}</button></form>`
		].join(''),
		200,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

/* The outcomes of "Yes, this was me": confirmed, already confirmed, or a link that cannot act here. */
export function passkeyConfirmOutcomePage(
	language: Language,
	outcome: 'confirmed' | 'already' | 'cannot'
): Response {
	const T = ACCOUNT_TEXTS[language];
	const [title, body, status] =
		outcome === 'confirmed'
			? [T.passkeyConfirmDoneTitle, T.passkeyConfirmed, 200]
			: outcome === 'already'
				? [T.passkeyConfirmDoneTitle, T.passkeyConfirmAlready, 200]
				: [T.passkeyConfirmCantTitle, T.passkeyConfirmCant, 400];
	const response = page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${esc(body)}</p>`,
		status,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function passkeyDisownGonePage(
	language: Language,
	service: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const response = page(
		T.disownNothingTitle,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.disownNothingTitle)}</h1><p>${html(T.passkeyDisownNothing, { service })}</p>`,
		400,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

/*
 * The outcome: the passkeys are gone; whether every session ended; and, where the person has a password, that it must
 * change now, with whether the reset mail went.
 */
export function passkeyDisownRefusedPage(
	language: Language,
	reason: string
): Response {
	const title = 'Passkey could not be removed';
	const response = page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${esc(reason)}</p>`,
		409,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function passkeyDisownDonePage(
	language: Language,
	outcome: {
		done: boolean;
		service: string;
		email: string;
		forgot: string;
		mail: 'sent' | 'refused' | 'none';
	}
): Response {
	const T = ACCOUNT_TEXTS[language];
	const title = outcome.done ? T.passkeyDisownDoneTitle : T.signOutFailedTitle;
	const values = {
		service: outcome.service,
		email: outcome.email,
		forgot: outcome.forgot
	};
	const parts = outcome.done
		? [
				`<p>${esc(T.passkeyDisownDone)}</p>`,
				...(outcome.mail === 'none'
					? []
					: [
							`<p>${esc(T.passkeyDisownPassword)}</p>`,
							`<p style="overflow-wrap:anywhere;">${html(outcome.mail === 'sent' ? T.signOutDoneMail : T.signOutDoneNoMail, values)}</p>`
						])
			]
		: [`<p>${esc(T.signOutFailed)}</p>`];
	const response = page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1>${parts.join('')}`,
		outcome.done ? 200 : 500,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

// ---------------------------------------------------------------- "This wasn't me" about a new sign-in (specs/138)

/* What confirming will do, said before it is done: for a person what happens to their password, for an administrator who is told. */
export type NotMeAfter =
	| { kind: 'reset' }
	| { kind: 'provider'; providers: string[] }
	| { kind: 'none' }
	| { kind: 'administrator' };

/* Opening the link only shows this; the form's POST is the act, so a mail scanner following the link changes nothing. */
export function notMeConfirmPage(
	language: Language,
	path: string,
	token: string,
	who: { service: string; email: string },
	after: NotMeAfter
): Response {
	const T = ACCOUNT_TEXTS[language];
	const then =
		after.kind === 'reset'
			? esc(T.signOutMail)
			: after.kind === 'provider'
				? html(T.signOutProvider, { providers: after.providers.join(', ') })
				: after.kind === 'administrator'
					? esc(T.notMeAdministrator)
					: null;
	const response = page(
		T.signOutTitle,
		[
			`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.signOutTitle)}</h1>`,
			`<p style="overflow-wrap:anywhere;">${html(T.notMeIntro, who)}</p>`,
			...(then === null ? [] : [`<p>${then}</p>`]),
			`<form method="post" action="${esc(path)}">${hidden({ token })}<button type="submit" style="${BUTTON}">${esc(T.signOutEverywhere)}</button></form>`
		].join(''),
		200,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function notMeGonePage(
	language: Language,
	service: string,
	forgot: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const response = page(
		T.notMeGoneTitle,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.notMeGoneTitle)}</h1><p>${html(T.notMeGone, { service, forgot })}</p>`,
		400,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function notMeAdministratorDonePage(
	language: Language,
	done: boolean
): Response {
	const T = ACCOUNT_TEXTS[language];
	const title = done ? T.signOutDoneTitle : T.signOutFailedTitle;
	const response = page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${esc(done ? T.notMeAdministratorDone : T.signOutFailed)}</p>`,
		done ? 200 : 500,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

// ---------------------------------------------------------------- recent sign-ins (specs/135)

function placeWords(row: OwnSignIn, T: AccountTexts): string {
	switch (row.place.kind) {
		case 'app':
			return row.place.name;
		case 'accountPage':
			return T.accountPageName;
		case 'gone':
			return T.deletedApp;
	}
}

function methodWords(row: OwnSignIn, T: AccountTexts): string {
	switch (row.method) {
		case 'password':
			return T.methodPassword;
		case 'password_code':
			return T.methodPasswordCode;
		case 'passkey':
			return T.methodPasskey;
		case 'provider':
			return row.provider
				? text(T.methodProvider, { provider: row.provider })
				: T.methodProviderGone;
	}
}

/* Brand names stay as they are in every language; only "other" and the joining words are the catalog's. */
function deviceWords(row: OwnSignIn, T: AccountTexts): string | null {
	if (!row.device) return null;
	const browser = BROWSER_NAMES[row.device.browser] ?? T.otherBrowser;
	const system = SYSTEM_NAMES[row.device.system];
	return system === null ? browser : text(T.browserOn, { browser, system });
}

function signInItem(row: OwnSignIn, language: Language, now: Date): string {
	const T = ACCOUNT_TEXTS[language];
	const ago = formatAgo(language, row.at.getTime(), now.getTime()) ?? T.justNow;
	const country = row.country ? countryWords(row.country, language) : null;
	const parts = [
		`${stamp(row.at, language)} (${esc(ago)})`,
		...[methodWords(row, T), deviceWords(row, T), country]
			.filter((part): part is string => part !== null)
			.map((part) => esc(part))
	];
	const mark = row.thisBrowser
		? ` · <strong>${esc(T.thisBrowser)}</strong>`
		: '';
	return `<li data-sign-in style="margin:0 0 12px; padding:0 0 12px; border-bottom:1px solid ${foxVar('box-border')};"><strong style="overflow-wrap:anywhere;">${esc(placeWords(row, T))}</strong>${mark}<br/><span style="${MUTED}">${parts.join(' · ')}</span></li>`;
}

export function signInsPage(
	frame: PageFrame,
	nav: AccountNav,
	view: OwnSignInsView,
	now: Date
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	let list: string;
	switch (view.state) {
		case 'off':
			list = `<p style="margin:8px 0;">${esc(T.signInsOff)}</p>`;
			break;
		case 'empty':
			list = `<p style="margin:8px 0;">${html(T.signInsEmpty, {
				date: formatDate(frame.language, view.since.getTime(), now.getTime())
			})}</p>`;
			break;
		case 'list':
			list = [
				`<p style="margin:8px 0;">${html(T.signInsIntro, { service: frame.service })}</p>`,
				`<ul style="list-style:none; padding:0; margin:16px 0;">${view.rows.map((row) => signInItem(row, frame.language, now)).join('')}</ul>`,
				`<p style="margin:8px 0; ${MUTED}">${esc(T.signInsLate)}</p>`
			].join('');
			break;
	}
	const body = [
		header(frame),
		`<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.signInsTitle)}</h1>`,
		`<p style="margin:0 0 8px; overflow-wrap:anywhere;">${htmlWith(T.signedInAs, { email: `<strong>${esc(frame.email)}</strong>` })} · <a href="${esc(frame.signOutHref)}" style="${LINK}">${esc(T.signOut)}</a></p>`,
		`<nav style="margin:0 0 8px;">${navLine(frame, nav)}</nav>`,
		list,
		`<h2 style="font-size:16px; margin:24px 0 8px;">${esc(T.notMe)}</h2>`,
		`<p><a href="${esc(`${frame.path}?confirm=1`)}" style="${DANGER_LINK}">${esc(T.signOutEverywhere)}</a></p>`
	].join('');
	const response = page(T.signInsTitle, body, 200, {
		wide: true,
		language: frame.language
	});
	// What a person's sign-ins were is theirs alone; no cache between them and the server keeps it.
	response.headers.set('cache-control', 'no-store');
	return response;
}

/* What the confirmation says about a password, decided by the route from the person and the project. */
export type SignOutMail = 'reset' | { providers: string[] } | 'none';

export function signOutConfirmPage(
	frame: PageFrame,
	xsrf: string,
	mail: SignOutMail
): Response {
	const T = ACCOUNT_TEXTS[frame.language];
	const password =
		mail === 'reset'
			? `<p>${esc(T.signOutMail)}</p>`
			: mail === 'none'
				? ''
				: `<p>${html(T.signOutProvider, {
						providers: formatList(frame.language, mail.providers)
					})}</p>`;
	const body = [
		header(frame),
		`<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.signOutTitle)}</h1>`,
		`<p style="margin:8px 0;">${esc(T.signOutEffect)}</p>`,
		password,
		`<form method="post" action="${esc(frame.path)}" style="display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-top:16px;">`,
		`<input type="hidden" name="xsrf" value="${esc(xsrf)}"/>`,
		`<button type="submit" style="${BUTTON}">${esc(T.signOutEverywhere)}</button>`,
		`<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>`,
		`</form>`
	].join('');
	const response = page(T.signOutTitle, body, 200, {
		wide: true,
		language: frame.language
	});
	response.headers.set('cache-control', 'no-store');
	return response;
}

export type SignOutOutcome =
	| {
			done: true;
			mail: 'sent' | 'refused' | 'none';
			email: string;
			forgot: string;
	  }
	| { done: false };

/* Shown as the answer to the act itself: the session it ended is not needed, and nothing in an address chooses it. */
export function signOutOutcomePage(
	language: Language,
	service: string,
	accountHref: string,
	outcome: SignOutOutcome
): Response {
	const T = ACCOUNT_TEXTS[language];
	const title = outcome.done ? T.signOutDoneTitle : T.signOutFailedTitle;
	let lines: string[] = [];
	if (!outcome.done) lines = [`<p>${esc(T.signOutFailed)}</p>`];
	else if (outcome.mail === 'sent') {
		lines = [`<p>${html(T.signOutDoneMail, { email: outcome.email })}</p>`];
	} else if (outcome.mail === 'refused') {
		lines = [
			`<p>${html(T.signOutDoneNoMail, { service, forgot: outcome.forgot })}</p>`
		];
	}
	const response = page(
		title,
		[
			`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1>`,
			...lines,
			`<p><a href="${esc(accountHref)}" style="${LINK}">${esc(T.backToAccount)}</a></p>`
		].join(''),
		outcome.done ? 200 : 500,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

// ---------------------------------------------------------------- standalone admin-sent passkey setup (specs/145 S14)

const SETUP_INPUT = `font-size:16px; min-height:36px; padding:0 10px; border:1px solid ${foxVar('field-border')}; border-radius:6px; width:100%; max-width:360px; box-sizing:border-box; margin:6px 0 12px; display:block;`;
const SETUP_ERROR = `background:${foxVar('danger-bg')}; border:1px solid ${foxVar('danger-border')}; color:${foxVar('danger-text')}; border-radius:6px; padding:8px 12px; margin:12px 0;`;

export function passkeySetupInvalidPage(
	language: Language,
	service: string
): Response {
	const T = ACCOUNT_TEXTS[language];
	const response = page(
		T.passkeySetupTitle,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.passkeySetupTitle)}</h1><p>${html(T.passkeySetupInvalid, { service })}</p>`,
		400,
		{ language }
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function passkeySetupTotpPage(input: {
	language: Language;
	path: string;
	service: string;
	email: string;
	token: string;
	project?: string;
	wrong?: boolean;
}): Response {
	const T = ACCOUNT_TEXTS[input.language];
	const fields: Record<string, string> = {
		action: 'totp',
		token: input.token,
		...(input.project ? { project: input.project } : {})
	};
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.passkeySetupTotpHeading)}</h1>`,
		`<p style="overflow-wrap:anywhere;">${html(T.passkeySetupTotpHint, { service: input.service, email: input.email })}</p>`,
		input.wrong
			? `<p role="alert" style="${SETUP_ERROR}">${esc(T.passkeySetupTotpWrong)}</p>`
			: '',
		`<form method="post" action="${esc(input.path)}">`,
		hidden(fields),
		`<label for="pk-setup-code" style="display:block;">${esc(T.passkeySetupTotpLabel)}</label>`,
		`<input id="pk-setup-code" name="code" inputmode="numeric" autocomplete="one-time-code" required style="${SETUP_INPUT}"/>`,
		`<button type="submit" style="${PRIMARY}">${esc(T.passkeySetupTotpButton)}</button>`,
		`</form>`
	].join('');
	const response = page(
		T.passkeySetupTotpHeading,
		body,
		input.wrong ? 400 : 200,
		{
			language: input.language
		}
	);
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function passkeySetupCreatePage(input: {
	language: Language;
	path: string;
	service: string;
	email: string;
	token: string;
	project?: string;
	options: string;
	script: string;
	notice?: string;
}): Response {
	const T = ACCOUNT_TEXTS[input.language];
	const errorText =
		input.notice === 'exists'
			? T.passkeyExists
			: input.notice === 'no_uv'
				? T.passkeyNoUserVerification
				: input.notice === 'expired'
					? T.passkeyTooLong
					: input.notice === 'failed'
						? T.passkeyAddFailed
						: undefined;
	const fields: Record<string, string> = {
		action: 'create',
		token: input.token,
		credential: '',
		...(input.project ? { project: input.project } : {})
	};
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.passkeySetupTitle)}</h1>`,
		`<p style="overflow-wrap:anywhere;">${html(T.passkeySetupIntro, { service: input.service, email: input.email })}</p>`,
		errorText
			? `<p role="alert" style="${SETUP_ERROR}">${esc(errorText)}</p>`
			: '',
		`<form method="post" action="${esc(input.path)}" data-passkey-add data-options="${esc(input.options)}" data-text-exists="${esc(T.passkeyExists)}" data-text-failed="${esc(T.passkeyAddFailed)}" data-text-no-uv="${esc(T.passkeyNoUserVerification)}" style="margin-top:12px;">`,
		hidden(fields),
		`<button type="button" disabled style="${PRIMARY}">${esc(T.passkeySetupButton)}</button>`,
		`<p data-passkey-status role="status" style="${MUTED}">${esc(T.passkeyNeedsScript)}</p>`,
		`</form>`,
		`<script src="${esc(input.script)}"></script>`
	].join('');
	const response = page(T.passkeySetupTitle, body, errorText ? 400 : 200, {
		language: input.language
	});
	response.headers.set('cache-control', 'no-store');
	return response;
}

export function passkeySetupDonePage(input: {
	language: Language;
	service: string;
	email: string;
	isAdmin: boolean;
	href: string;
}): Response {
	const T = ACCOUNT_TEXTS[input.language];
	const body = [
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(T.passkeySetupDoneTitle)}</h1>`,
		`<p style="overflow-wrap:anywhere;">${html(T.passkeySetupDone, { service: input.service, email: input.email })}</p>`,
		`<p><a href="${esc(input.href)}" style="${LINK}">${esc(input.isAdmin ? T.passkeySetupConsole : T.backToAccount)}</a></p>`
	].join('');
	const response = page(T.passkeySetupDoneTitle, body, 200, {
		language: input.language
	});
	response.headers.set('cache-control', 'no-store');
	return response;
}
