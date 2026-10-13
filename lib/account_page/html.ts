import { esc } from '../html/escape.js';
import { page } from '../interactions/plainPage.js';
import { CONSENT_TEXTS } from '../interactions/consentTexts.js';
import type {
	ConsentGroup,
	ConsentItem,
	RarBlock
} from '../interactions/consentView.js';
import { ACCOUNT_PAGE_TEXTS as T } from './texts.js';
import type { ApplicationRow } from './view.js';

/*
 * The connected-applications page as markup (specs/095). The plain, script-free family: every step — the list,
 * the confirmation, the removal — is a link or a form, so all of it works with scripts off (R10). Every value
 * reaching the markup goes through `esc`; the sentences come from the catalog.
 *
 * Contrast: body text #1f1f1f and secondary #595959 on white are both above 4.5:1, as are the link and
 * button colours. Every control is at least 24 px tall, and none removes the browser's focus ring.
 */

const MUTED = 'color:#595959;';
const LINK =
	'color:#0958d9; display:inline-block; min-height:24px; line-height:24px;';
const DANGER_LINK =
	'color:#a8071a; display:inline-block; min-height:24px; line-height:24px;';
const BUTTON =
	'background:#a8071a; color:#fff; border:0; border-radius:6px; padding:0 16px; min-height:32px; font-size:14px; cursor:pointer;';

export interface PageFrame {
	service: string;
	logoSrc: string;
	/* The page's own path: links and the form stay on whatever origin served it. */
	path: string;
	signOutHref: string;
	email: string;
}

function header(frame: PageFrame): string {
	return `<div style="display:flex; align-items:center; gap:8px; margin-bottom:16px; ${MUTED}"><img src="${esc(frame.logoSrc)}" alt="" width="24" height="24"/><span>${esc(frame.service)}</span></div>`;
}

function stamp(date: Date): string {
	const iso = date.toISOString();
	return `<time datetime="${esc(iso)}">${esc(`${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`)}</time>`;
}

function capitalised(text: string): string {
	return text.charAt(0).toUpperCase() + text.slice(1);
}

function itemText(item: ConsentItem): string | undefined {
	if (item.category)
		return capitalised(CONSENT_TEXTS.categories[item.category]);
	return item.text;
}

function codes(list: readonly string[]): string {
	return list.map((c) => `<code>${esc(c)}</code>`).join(', ');
}

function rarList(blocks: readonly RarBlock[]): string {
	return blocks
		.map(
			(block) =>
				`<li>${esc(block.label)}${block.fields.length ? `<ul>${block.fields.map((f) => `<li>${esc(CONSENT_TEXTS.rarFields[f.field])}: ${esc(f.values)}</li>`).join('')}</ul>` : ''}</li>`
		)
		.join('');
}

function groupList(group: ConsentGroup): string {
	const lines: string[] = [];
	for (const item of group.items) {
		const text = itemText(item);
		lines.push(`<li>${text ? esc(text) : codes(item.codes)}</li>`);
	}
	for (const block of group.resources) {
		const inner = block.items
			.map((item) => {
				const text = itemText(item);
				return `<li>${text ? esc(text) : codes(item.codes)}</li>`;
			})
			.join('');
		lines.push(
			`<li>${esc(CONSENT_TEXTS.resource.heading)} ${esc(block.name ?? block.host)}<ul>${inner}</ul></li>`
		);
	}
	const rar = rarList(group.rar);
	return lines.length || rar
		? `<ul style="margin:4px 0 8px; padding-left:20px;">${lines.join('')}${rar}</ul>`
		: '';
}

function technicalNames(row: ApplicationRow): string {
	const all = new Set<string>();
	for (const group of [row.groups.see, row.groups.act]) {
		for (const item of group.items) item.codes.forEach((c) => all.add(c));
		for (const block of group.resources)
			for (const item of block.items) item.codes.forEach((c) => all.add(c));
	}
	if (!all.size) return '';
	return `<details style="margin:4px 0;"><summary style="${LINK} cursor:pointer;">${esc(T.technicalNames)}</summary><p style="${MUTED} margin:4px 0;">${codes([...all])}</p></details>`;
}

function permissions(row: ApplicationRow, service: string): string {
	if (row.trusted) {
		return `<p style="margin:8px 0;">${esc(T.trusted(service))}</p>`;
	}
	const parts: string[] = [];
	const { see, act, other } = row.groups;
	const sections: Array<[string, ConsentGroup]> = [
		[T.canSee, see],
		[T.canDo, act],
		[T.other, other]
	];
	for (const [heading, group] of sections) {
		const list = groupList(group);
		if (list) {
			parts.push(
				`<h3 style="font-size:14px; margin:12px 0 0;">${esc(heading)}</h3>${list}`
			);
		}
	}
	if (row.confirmsIdentity) {
		parts.push(`<p style="margin:8px 0;">${esc(T.confirmIdentity)}</p>`);
	}
	return parts.join('') + technicalNames(row);
}

function logoTile(row: ApplicationRow): string {
	if (!row.logo) return '';
	return `<span style="flex:none; width:40px; height:40px; background:#f6f7f9; border:1px solid #e6e8eb; border-radius:8px; display:flex; align-items:center; justify-content:center;"><img src="${esc(row.logo)}" alt="${esc(row.name)}" width="32" height="32" style="object-fit:contain; display:block;"/></span>`;
}

function where(row: ApplicationRow): string {
	if (row.hosts.length) return T.hosts(row.hosts, row.moreHosts);
	if (row.onDevice) return T.onThisDevice;
	return '';
}

function section(row: ApplicationRow, index: number, frame: PageFrame): string {
	const id = `app-${index}`;
	const whereLine = where(row);
	const revokeHref = `${frame.path}?revoke=${encodeURIComponent(row.clientId)}`;
	return `<section aria-labelledby="${id}" style="border-top:1px solid #e6e8eb; padding:16px 0;">
<div style="display:flex; gap:12px; align-items:flex-start;">${logoTile(row)}<div style="min-width:0; flex:1;"><h2 id="${id}" style="font-size:18px; margin:0; overflow-wrap:anywhere;">${esc(row.name)}</h2>${whereLine ? `<p style="${MUTED} margin:4px 0 0; overflow-wrap:anywhere;">${esc(whereLine)}</p>` : ''}</div></div>
${permissions(row, frame.service)}
<p style="${MUTED} margin:8px 0 0;">${esc(T.given)} ${stamp(row.givenAt)}${row.lastTokenAt ? `<br/>${esc(T.lastToken)} ${stamp(row.lastTokenAt)}` : ''}</p>
${row.keepsAccess ? `<p style="margin:8px 0 0;"><strong>${esc(T.keepsAccess)}</strong></p>` : ''}
<p style="margin:8px 0 0;"><a href="${esc(revokeHref)}" style="${DANGER_LINK}">${esc(T.remove)}<span style="position:absolute; width:1px; height:1px; overflow:hidden; clip:rect(0 0 0 0);">: ${esc(row.name)}</span></a></p>
</section>`;
}

export function listPage(
	frame: PageFrame,
	rows: readonly ApplicationRow[],
	notice?: string
): Response {
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px;">${esc(T.title)}</h1>
<p style="margin:0 0 8px; overflow-wrap:anywhere;">${esc(T.signedInAs)} <strong>${esc(frame.email)}</strong> · <a href="${esc(frame.signOutHref)}" style="${LINK}">${esc(T.signOut)}</a></p>
<div role="status">${notice ? `<p style="background:#f6ffed; border:1px solid #b7eb8f; border-radius:6px; padding:8px 12px; margin:8px 0;">${esc(notice)}</p>` : ''}</div>
${rows.length ? `<p style="margin:8px 0 16px;">${esc(T.intro)}</p>${rows.map((row, i) => section(row, i, frame)).join('')}` : `<p style="margin:8px 0;">${esc(T.empty)}</p>`}`;
	return page(T.title, body, 200, { wide: true });
}

export function confirmationPage(
	frame: PageFrame,
	row: ApplicationRow,
	xsrf: string
): Response {
	const body = `${header(frame)}<h1 style="font-size:24px; margin:0 0 8px; overflow-wrap:anywhere;">${esc(T.confirmTitle(row.name))}</h1>
<p style="margin:8px 0;">${esc(T.confirmEffect(row.name))} ${esc(row.trusted ? T.confirmReturnsSilently : T.confirmAsksAgain)}</p>
<form method="post" action="${esc(frame.path)}" style="display:flex; flex-wrap:wrap; gap:16px; align-items:center; margin-top:16px;">
<input type="hidden" name="clientId" value="${esc(row.clientId)}"/>
<input type="hidden" name="xsrf" value="${esc(xsrf)}"/>
<button type="submit" style="${BUTTON}">${esc(T.remove)}</button>
<a href="${esc(frame.path)}" style="${LINK}">${esc(T.cancel)}</a>
</form>`;
	return page(T.confirmTitle(row.name), body, 200, { wide: true });
}

/* A short page for an outcome that is not the list: an expired or abandoned sign-in, a refused request. */
export function outcomePage(
	title: string,
	message: string,
	path: string,
	status: number
): Response {
	return page(
		title,
		`<h1 style="font-size:20px; margin:0 0 8px;">${esc(title)}</h1><p>${esc(message)}</p><p><a href="${esc(path)}" style="${LINK}">${esc(T.tryAgain)}</a></p>`,
		status
	);
}
