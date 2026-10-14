/*
 * Turning a catalogue entry into text.
 *
 * An entry is a whole sentence with named slots — `'Sign in to {app}'` — so a translator can put the name
 * where their language wants it; the consent page used to split sentences around names, which baked English
 * word order into the component. Only the catalogue's template is ever split on slots. A value is inserted
 * after the split and never looked at again, so an application calling itself `{service}`, `<b>` or U+202E is
 * shown as exactly that, and each value sits in `<bdi>` so its direction cannot reorder the sentence around it.
 *
 * Plurals are objects keyed by the CLDR categories of each language (`one`/`few`/`many`/`other` in Russian,
 * `other` alone in Chinese), chosen by Intl.PluralRules; the catalogue test checks each language has exactly
 * the categories it needs. An object with an `other` key IS a plural, so no ordinary group of texts may use
 * `other` as a key name.
 */

import { Fragment, type ReactNode } from 'react';

import { esc } from '../html/escape.js';
import { FORMAT_LOCALE, type Language } from './languages.js';

export interface Plural {
	zero?: string;
	one?: string;
	two?: string;
	few?: string;
	many?: string;
	other: string;
}

/*
 * The shape every translation must have: the same keys as English, a string wherever English has a string and a
 * plural wherever English has one. The words are free; the structure is not.
 */
export type Shape<T> = T extends string
	? string
	: T extends { other: string }
		? Plural
		: { readonly [K in keyof T]: Shape<T[K]> };

const SLOT = /\{([a-zA-Z][a-zA-Z0-9]*)\}/g;

type Piece = { text: string } | { slot: string };

const pieceCache = new Map<string, Piece[]>();

function pieces(template: string): Piece[] {
	let cached = pieceCache.get(template);
	if (cached) return cached;
	cached = [];
	let last = 0;
	for (const match of template.matchAll(SLOT)) {
		if (match.index > last) {
			cached.push({ text: template.slice(last, match.index) });
		}
		cached.push({ slot: match[1] });
		last = match.index + match[0].length;
	}
	if (last < template.length) cached.push({ text: template.slice(last) });
	pieceCache.set(template, cached);
	return cached;
}

export function placeholders(template: string): Set<string> {
	return new Set(
		pieces(template).flatMap((piece) => ('slot' in piece ? [piece.slot] : []))
	);
}

type TextValue = string | number;

/* Plain text: a `<title>`, an attribute, an email subject or text part. The sink escapes it. */
export function text(
	template: string,
	values: Readonly<Record<string, TextValue>> = {}
): string {
	return pieces(template)
		.map((piece) =>
			'text' in piece ? piece.text : String(values[piece.slot] ?? '')
		)
		.join('');
}

/* Escaped HTML for the plain pages and email HTML parts: each value escaped and isolated. */
export function html(
	template: string,
	values: Readonly<Record<string, TextValue>> = {}
): string {
	return pieces(template)
		.map((piece) =>
			'text' in piece
				? esc(piece.text)
				: `<bdi>${esc(String(values[piece.slot] ?? ''))}</bdi>`
		)
		.join('');
}

/*
 * For a slot whose value is already markup the caller built — a link, a bold name. Only the template is
 * escaped here; the caller owns isolating its own values.
 */
export function htmlWith(
	template: string,
	values: Readonly<Record<string, string>>
): string {
	return pieces(template)
		.map((piece) =>
			'text' in piece ? esc(piece.text) : (values[piece.slot] ?? '')
		)
		.join('');
}

/*
 * React: a string or number value is wrapped in `<bdi>`; a node value (a link, a styled name) is rendered as
 * given, because the caller that built it has already isolated what it contains.
 */
export function Message({
	t,
	values = {}
}: {
	t: string;
	values?: Readonly<Record<string, ReactNode>>;
}): ReactNode {
	return (
		<>
			{pieces(t).map((piece, index) => {
				if ('text' in piece)
					return <Fragment key={index}>{piece.text}</Fragment>;
				const value = values[piece.slot];
				return typeof value === 'string' || typeof value === 'number' ? (
					<bdi key={index}>{value}</bdi>
				) : (
					<Fragment key={index}>{value}</Fragment>
				);
			})}
		</>
	);
}

const pluralRules = new Map<Language, Intl.PluralRules>();

/* The plural form for `count`, with `{count}` left in it for the renderer to fill. */
export function plural(
	entry: Plural,
	count: number,
	language: Language
): string {
	let rules = pluralRules.get(language);
	if (rules === undefined) {
		rules = new Intl.PluralRules(FORMAT_LOCALE[language]);
		pluralRules.set(language, rules);
	}
	// select() returns one of the six CLDR names, which are exactly Plural's keys.
	const category = rules.select(count);
	return entry[category] ?? entry.other;
}
